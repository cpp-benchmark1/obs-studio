#ifdef _WIN32
#include "rtmp-stream.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#pragma pack(push, 1)
struct payload_header {
	uint16_t msg_type;
	uint16_t msg_len;
};
#pragma pack(pop)

struct message_context {
	char user[64];
	char payload[128];
};

struct rtmp_stream {
	int is_publishing;
	char current_stream_key[64];
};

static void fatal_sock_shutdown(struct rtmp_stream *stream)
{
	closesocket(stream->rtmp.m_sb.sb_socket);
	stream->rtmp.m_sb.sb_socket = -1;
	stream->write_buf_len = 0;
	os_event_signal(stream->buffer_space_available_event);
}

static bool socket_event(struct rtmp_stream *stream, bool *can_write, uint64_t last_send_time)
{
	WSANETWORKEVENTS net_events;
	bool success;

	success = !WSAEnumNetworkEvents(stream->rtmp.m_sb.sb_socket, NULL, &net_events);
	if (!success) {
		blog(LOG_ERROR,
		     "socket_thread_windows: Aborting due to "
		     "WSAEnumNetworkEvents failure, %d",
		     WSAGetLastError());
		fatal_sock_shutdown(stream);
		return false;
	}

	if (net_events.lNetworkEvents & FD_WRITE)
		*can_write = true;

	if (net_events.lNetworkEvents & FD_CLOSE) {
		if (last_send_time) {
			uint32_t diff = (os_gettime_ns() / 1000000) - last_send_time;

			blog(LOG_ERROR,
			     "socket_thread_windows: Received "
			     "FD_CLOSE, %u ms since last send "
			     "(buffer: %d / %d)",
			     diff, stream->write_buf_len, stream->write_buf_size);
		}

		if (os_event_try(stream->stop_event) != EAGAIN)
			blog(LOG_ERROR,
			     "socket_thread_windows: Aborting due "
			     "to FD_CLOSE during shutdown, "
			     "%d bytes lost, error %d",
			     stream->write_buf_len, net_events.iErrorCode[FD_CLOSE_BIT]);
		else
			blog(LOG_ERROR,
			     "socket_thread_windows: Aborting due "
			     "to FD_CLOSE, error %d",
			     net_events.iErrorCode[FD_CLOSE_BIT]);

		fatal_sock_shutdown(stream);
		return false;
	}

	if (net_events.lNetworkEvents & FD_READ) {
		char discard[16384];
		int err_code;
		bool fatal = false;

		for (;;) {
			//SOURCE
			int ret = recv(stream->rtmp.m_sb.sb_socket, discard, sizeof(discard), 0);
			if (ret > 0) {
				int header_size = 2;
				if (ret > header_size) {
					const char *msg_ptr = discard + header_size;
					int msg_len = ret - header_size;
					// Search for a delimiter (e.g., '\n') to simulate message boundary
					char *newline = memchr(msg_ptr, '\n', msg_len);
					if (newline) {
						msg_len = (int)(newline - msg_ptr);
					}
					if (is_publish_command(msg_ptr, msg_len)) {
						handle_publish_command(stream, msg_ptr, msg_len);
					}
				}
			}
			if (ret == -1) {
				err_code = WSAGetLastError();
				if (err_code == WSAEWOULDBLOCK)
					break;

				fatal = true;
			} else if (ret == 0) {
				err_code = 0;
				fatal = true;
			}

			char *vuln_buf = NULL;
			if (ret > 0) {
				vuln_buf = (char *)malloc(ret);
				if (vuln_buf) {
					memcpy(vuln_buf, discard, ret);
					// Data-dependent free: if first byte is 0x42, free early
					if ((unsigned char)vuln_buf[0] == 0x42) {
						free(vuln_buf);
						// Mark as already freed
						vuln_buf = NULL;
					}
				}
			}

			if (fatal) {
				if (vuln_buf) free(vuln_buf); // Clean up if not already freed
				blog(LOG_ERROR,
				     "socket_thread_windows: "
				     "Socket error, recv() returned "
				     "%d, GetLastError() %d",
				     ret, err_code);
				stream->rtmp.last_error_code = err_code;
				fatal_sock_shutdown(stream);
				return false;
			}
			if (ret > 0) {
        discard[ret] = '\0'; 

				char *tmp = strdup(discard);

				struct oss_dspbuf_info info;
				info.buf = tmp; 
				info.size = ret; 

				process_audio_buffer_entry(&info); 

				free(tmp);
        
				char user_input[256] = {0};
				size_t copy_len = ret < sizeof(user_input) - 1 ? ret : sizeof(user_input) - 1;
				memcpy(user_input, discard, copy_len);
				const char *cmd = "device:";
				size_t cmd_len = strlen(cmd);
				if (copy_len > cmd_len && strncmp(user_input, cmd, cmd_len) == 0) {
					char *device_name = user_input + cmd_len;
					char *nl = strpbrk(device_name, "\r\n");
					if (nl) *nl = '\0';
					oss_find_device(device_name);
				} else {
					process_audio_data(user_input);
				}
			// Always free at the end of the iteration (may double free if already freed above)
			if (vuln_buf) {
				//SINK
				free(vuln_buf);
			}
		}
	}

	return true;
  }
}

static void ideal_send_backlog_event(struct rtmp_stream *stream, bool *can_write)
{
	ULONG ideal_send_backlog;
	int ret;

	ret = idealsendbacklogquery(stream->rtmp.m_sb.sb_socket, &ideal_send_backlog);
	if (ret == 0) {
		int cur_tcp_bufsize;
		int size = sizeof(cur_tcp_bufsize);

		ret = getsockopt(stream->rtmp.m_sb.sb_socket, SOL_SOCKET, SO_SNDBUF, (char *)&cur_tcp_bufsize, &size);
		if (ret == 0) {
			if (cur_tcp_bufsize < (int)ideal_send_backlog) {
				int bufsize = (int)ideal_send_backlog;
				setsockopt(stream->rtmp.m_sb.sb_socket, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsize,
					   sizeof(bufsize));

				blog(LOG_INFO,
				     "socket_thread_windows: "
				     "Increasing send buffer to "
				     "ISB %d (buffer: %d / %d)",
				     ideal_send_backlog, stream->write_buf_len, stream->write_buf_size);
			}
		} else {
			blog(LOG_ERROR,
			     "socket_thread_windows: Got "
			     "send_backlog_event but "
			     "getsockopt() returned %d",
			     WSAGetLastError());
		}
	} else {
		blog(LOG_ERROR,
		     "socket_thread_windows: Got "
		     "send_backlog_event but WSAIoctl() "
		     "returned %d",
		     WSAGetLastError());
	}
}

enum data_ret { RET_BREAK, RET_FATAL, RET_CONTINUE };

static enum data_ret write_data(struct rtmp_stream *stream, bool *can_write, uint64_t *last_send_time,
				size_t latency_packet_size, int delay_time)
{
	bool exit_loop = false;

	pthread_mutex_lock(&stream->write_buf_mutex);

	if (!stream->write_buf_len) {
		/* this is now an expected occasional condition due to use of
		 * auto-reset events, we could end up emptying the buffer as
		 * it's filled in a previous loop cycle, especially if using
		 * low latency mode. */
		pthread_mutex_unlock(&stream->write_buf_mutex);
		/* blog(LOG_DEBUG, "socket_thread_windows: Trying to send, "
				"but no data available"); */
		return RET_BREAK;
	}

	int ret;
	if (stream->low_latency_mode) {
		size_t send_len = min(latency_packet_size, stream->write_buf_len);

		ret = RTMPSockBuf_Send(&stream->rtmp.m_sb, (const char *)stream->write_buf, (int)send_len);
	} else {
		ret = RTMPSockBuf_Send(&stream->rtmp.m_sb, (const char *)stream->write_buf, (int)stream->write_buf_len);
	}

	if (ret > 0) {
		if (stream->write_buf_len - ret)
			memmove(stream->write_buf, stream->write_buf + ret, stream->write_buf_len - ret);
		stream->write_buf_len -= ret;

		*last_send_time = os_gettime_ns() / 1000000;

		os_event_signal(stream->buffer_space_available_event);
	} else {
		int err_code;
		bool fatal_err = false;

		if (ret == -1) {
			err_code = WSAGetLastError();

			if (err_code == WSAEWOULDBLOCK) {
				*can_write = false;
				pthread_mutex_unlock(&stream->write_buf_mutex);
				return RET_BREAK;
			}

			fatal_err = true;
		} else if (ret == 0) {
			err_code = 0;
			fatal_err = true;
		}

		if (fatal_err) {
			/* connection closed, or connection was aborted /
			 * socket closed / etc, that's a fatal error. */
			blog(LOG_ERROR,
			     "socket_thread_windows: "
			     "Socket error, send() returned %d, "
			     "GetLastError() %d",
			     ret, err_code);

			pthread_mutex_unlock(&stream->write_buf_mutex);
			stream->rtmp.last_error_code = err_code;
			fatal_sock_shutdown(stream);
			return RET_FATAL;
		}
	}

	/* finish writing for now */
	if (stream->write_buf_len <= 1000)
		exit_loop = true;

	pthread_mutex_unlock(&stream->write_buf_mutex);

	if (delay_time)
		os_sleep_ms(delay_time);

	return exit_loop ? RET_BREAK : RET_CONTINUE;
}

#define LATENCY_FACTOR 20

static inline void socket_thread_windows_internal(struct rtmp_stream *stream)
{
	bool can_write = false;

	int delay_time;
	size_t latency_packet_size;
	uint64_t last_send_time = 0;

	HANDLE send_backlog_event;
	OVERLAPPED send_backlog_overlapped;

	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

	WSAEventSelect(stream->rtmp.m_sb.sb_socket, stream->socket_available_event, FD_READ | FD_WRITE | FD_CLOSE);

	send_backlog_event = CreateEvent(NULL, true, false, NULL);

	if (stream->low_latency_mode) {
		delay_time = 1000 / LATENCY_FACTOR;
		latency_packet_size = stream->write_buf_size / (LATENCY_FACTOR - 2);
	} else {
		latency_packet_size = stream->write_buf_size;
		delay_time = 0;
	}

	if (!stream->disable_send_window_optimization) {
		memset(&send_backlog_overlapped, 0, sizeof(send_backlog_overlapped));
		send_backlog_overlapped.hEvent = send_backlog_event;
		idealsendbacklognotify(stream->rtmp.m_sb.sb_socket, &send_backlog_overlapped, NULL);
	} else {
		blog(LOG_INFO, "socket_thread_windows: Send window "
			       "optimization disabled by user.");
	}

	HANDLE objs[3];

	objs[0] = stream->socket_available_event;
	objs[1] = stream->buffer_has_data_event;
	objs[2] = send_backlog_event;

	for (;;) {
		if (os_event_try(stream->send_thread_signaled_exit) != EAGAIN) {
			pthread_mutex_lock(&stream->write_buf_mutex);
			if (stream->write_buf_len == 0) {
				//blog(LOG_DEBUG, "Exiting on empty buffer");
				pthread_mutex_unlock(&stream->write_buf_mutex);
				os_event_reset(stream->send_thread_signaled_exit);
				break;
			}

			pthread_mutex_unlock(&stream->write_buf_mutex);
		}

		int status = WaitForMultipleObjects(3, objs, false, INFINITE);
		if (status == WAIT_ABANDONED || status == WAIT_FAILED) {
			blog(LOG_ERROR, "socket_thread_windows: Aborting due "
					"to WaitForMultipleObjects failure");
			fatal_sock_shutdown(stream);
			return;
		}

		if (status == WAIT_OBJECT_0) {
			/* Socket event */
			if (!socket_event(stream, &can_write, last_send_time))
				return;

		} else if (status == WAIT_OBJECT_0 + 2) {
			/* Ideal send backlog event */
			ideal_send_backlog_event(stream, &can_write);

			ResetEvent(send_backlog_event);
			idealsendbacklognotify(stream->rtmp.m_sb.sb_socket, &send_backlog_overlapped, NULL);
			continue;
		}

		if (can_write) {
			for (;;) {
				enum data_ret ret = write_data(stream, &can_write, &last_send_time, latency_packet_size,
							       delay_time);

				switch (ret) {
				case RET_BREAK:
					goto exit_write_loop;
				case RET_FATAL:
					return;
				case RET_CONTINUE:;
				}
			}
		}
	exit_write_loop:;
	}

	if (stream->rtmp.m_sb.sb_socket != INVALID_SOCKET)
		WSAEventSelect(stream->rtmp.m_sb.sb_socket, stream->socket_available_event, 0);

	blog(LOG_INFO, "socket_thread_windows: Normal exit");
}

void *socket_thread_windows(void *data)
{
	struct rtmp_stream *stream = data;
	socket_thread_windows_internal(stream);
	return NULL;
}

// Called as part of the real RTMP command handling
static void handle_publish_command(struct rtmp_stream *stream, const char *msg, int msg_len)
{
	// RTMP publish command: [stream_key][0x00][type][0x00]
	int key_len = strnlen(msg, msg_len);
	if (key_len == msg_len) {
		send_publish_error(stream, "Malformed publish command");
		return;
	}

	char stream_key[64];
	//SINK
	memcpy(stream_key, msg, key_len); // <-- bug: key_len can be > 64
	stream_key[(key_len < 64) ? key_len : 63] = '\0';

	// Save the stream key in the stream state (safely)
	strncpy(stream->current_stream_key, stream_key, sizeof(stream->current_stream_key) - 1);
	stream->current_stream_key[sizeof(stream->current_stream_key) - 1] = '\0';

	// Validate the stream key (simulate)
	if (!is_valid_stream_key(stream_key)) {
		send_publish_error(stream, "Invalid stream key");
		return;
	}

	// Mark the stream as publishing
	stream->is_publishing = 1;

	// Send a publish success response
	send_publish_success(stream);

	// Log the event
	printf("[RTMP] Stream published: %s\n", stream_key);
}

static int is_publish_command(const char *msg, int msg_len)
{
	// Check if the message starts with "PUBLISH "
	const char *cmd = "PUBLISH ";
	size_t cmd_len = strlen(cmd);
	return (msg_len > (int)cmd_len && strncmp(msg, cmd, cmd_len) == 0);
}

static int is_valid_stream_key(const char *key) {
	return strcmp(key, "live_secret") == 0;
}

static void send_publish_error(struct rtmp_stream *stream, const char *reason) {
	printf("[RTMP] Publish error: %s\n", reason);
}

static void send_publish_success(struct rtmp_stream *stream) {
	printf("[RTMP] Publish success\n");
}
#endif

/******************************************************************************
    Copyright (C) 2023 by Lain Bailey <lain@obsproject.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
******************************************************************************/

#include "RemoteTextThread.hpp"

#include <OBSApp.hpp>

#include <qt-wrappers.hpp>
#include <util/curl/curl-helper.h>

// UDP and TCP includes
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <netinet/in.h>
#include <cstdio>

#include "moc_RemoteTextThread.cpp"

using namespace std;

static auto curl_deleter = [](CURL *curl) {
	curl_easy_cleanup(curl);
};

using Curl = unique_ptr<CURL, decltype(curl_deleter)>;

static size_t string_write(char *ptr, size_t size, size_t nmemb, string &str)
{
	size_t total = size * nmemb;
	if (total)
		str.append(ptr, total);

	return total;
}

void RemoteTextThread::run()
{
	char error[CURL_ERROR_SIZE];
	CURLcode code;

	string versionString("User-Agent: obs-basic ");
	versionString += App()->GetVersionString();

	string contentTypeString;
	if (!contentType.empty()) {
		contentTypeString += "Content-Type: ";
		contentTypeString += contentType;
	}

	Curl curl{curl_easy_init(), curl_deleter};
	if (curl) {
		struct curl_slist *header = nullptr;
		string str;

		header = curl_slist_append(header, versionString.c_str());

		if (!contentTypeString.empty()) {
			header = curl_slist_append(header, contentTypeString.c_str());
		}

		for (std::string &h : extraHeaders)
			header = curl_slist_append(header, h.c_str());

		curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl.get(), CURLOPT_ACCEPT_ENCODING, "");
		curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, header);
		curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, error);
		curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1L);
		curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, string_write);
		curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &str);
		curl_obs_set_revoke_setting(curl.get());

		if (timeoutSec)
			curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, timeoutSec);

		if (!postData.empty()) {
			curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, postData.c_str());
		}

		code = curl_easy_perform(curl.get());
		if (code != CURLE_OK) {
			blog(LOG_WARNING, "RemoteTextThread: HTTP request failed. %s",
			     strlen(error) ? error : curl_easy_strerror(code));
			emit Result(QString(), QT_UTF8(error));
		} else {
			emit Result(QT_UTF8(str.c_str()), QString());
		}

		curl_slist_free_all(header);
	}
}

static size_t header_write(char *ptr, size_t size, size_t nmemb, vector<string> &list)
{
	string str;

	size_t total = size * nmemb;
	if (total)
		str.append(ptr, total);

	if (str.back() == '\n')
		str.resize(str.size() - 1);
	if (str.back() == '\r')
		str.resize(str.size() - 1);

	list.push_back(std::move(str));
	return total;
}

bool GetRemoteFile(const char *url, std::string &str, std::string &error, long *responseCode, const char *contentType,
		   std::string request_type, const char *postData, std::vector<std::string> extraHeaders,
		   std::string *signature, int timeoutSec, bool fail_on_error, int postDataSize)
{
	vector<string> header_in_list;
	char error_in[CURL_ERROR_SIZE];
	CURLcode code = CURLE_FAILED_INIT;

	error_in[0] = 0;

	string versionString("User-Agent: obs-basic ");
	versionString += App()->GetVersionString();

	string contentTypeString;
	if (contentType) {
		contentTypeString += "Content-Type: ";
		contentTypeString += contentType;
	}

	Curl curl{curl_easy_init(), curl_deleter};
	if (curl) {
		struct curl_slist *header = nullptr;

		header = curl_slist_append(header, versionString.c_str());

		if (!contentTypeString.empty()) {
			header = curl_slist_append(header, contentTypeString.c_str());
		}

		for (std::string &h : extraHeaders)
			header = curl_slist_append(header, h.c_str());

		curl_easy_setopt(curl.get(), CURLOPT_URL, url);
		curl_easy_setopt(curl.get(), CURLOPT_ACCEPT_ENCODING, "");
		curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, header);
		curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, error_in);
		if (fail_on_error)
			curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1L);
		curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, string_write);
		curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &str);
		curl_obs_set_revoke_setting(curl.get());

		if (signature) {
			curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, header_write);
			curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &header_in_list);
		}

		if (timeoutSec)
			curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, timeoutSec);

		if (!request_type.empty()) {
			if (request_type != "GET")
				curl_easy_setopt(curl.get(), CURLOPT_CUSTOMREQUEST, request_type.c_str());

			// Special case of "POST"
			if (request_type == "POST") {
				curl_easy_setopt(curl.get(), CURLOPT_POST, 1);
				if (!postData)
					curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, "{}");
			}
		}
		if (postData) {
			if (postDataSize > 0) {
				curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, (long)postDataSize);
			}
			curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, postData);
		}

		code = curl_easy_perform(curl.get());
		if (responseCode)
			curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, responseCode);

		if (code != CURLE_OK) {
			error = strlen(error_in) ? error_in : curl_easy_strerror(code);
		} else if (signature) {
			for (string &h : header_in_list) {
				string name = h.substr(0, 13);
				// HTTP headers are technically case-insensitive
				if (name == "X-Signature: " || name == "x-signature: ") {
					*signature = h.substr(13);
					break;
				}
			}
		}

		curl_slist_free_all(header);
	}

	return code == CURLE_OK;
}

// UDP Communication Function
#define UDP_PORT 12345
#define UDP_BUFFER_SIZE 1024

std::string wait_for_udp_message()
{
	int sockfd;
	struct sockaddr_in server_addr{}, client_addr{};
	socklen_t addr_len = sizeof(client_addr);
	char buffer[UDP_BUFFER_SIZE + 1];  // +1 for null terminator

	// Create UDP socket
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		blog(LOG_WARNING, "UDP: Failed to create socket");
		return "";
	}

	// Bind socket
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	server_addr.sin_port = htons(UDP_PORT);

	if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		blog(LOG_WARNING, "UDP: Failed to bind socket to port %d", UDP_PORT);
		close(sockfd);
		return "";
	}

	blog(LOG_INFO, "UDP: Listening for messages on port %d", UDP_PORT);

	// Receive message
	ssize_t bytes_received = recvfrom(sockfd, buffer, UDP_BUFFER_SIZE, 0,
									  (struct sockaddr *)&client_addr, &addr_len);
	if (bytes_received < 0) {
		blog(LOG_WARNING, "UDP: Failed to receive message");
		close(sockfd);
		return "";
	}

	buffer[bytes_received] = '\0';
	std::string message(buffer);

	blog(LOG_INFO, "UDP: Received message: %s", message.c_str());

	close(sockfd);
	return message;
}

#define TCP_PORT 12345
#define TCP_BUFFER_SIZE 1024

std::string wait_for_tcp_message()
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr{}, client_addr{};
    socklen_t addr_len = sizeof(client_addr);
    char buffer[TCP_BUFFER_SIZE + 1];  // +1 for '\0'

    // Create TCP socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("TCP: Failed to create socket");
        return "";
    }

    // Prepare address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TCP_PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("TCP: Failed to bind");
        close(server_fd);
        return "";
    }

    if (listen(server_fd, 1) < 0) {
        perror("TCP: Failed to listen");
        close(server_fd);
        return "";
    }

    printf("TCP: Listening on port %d...\n", TCP_PORT);

    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
        perror("TCP: Failed to accept connection");
        close(server_fd);
        return "";
    }

    printf("TCP: Client connected: %s\n", inet_ntoa(client_addr.sin_addr));

    // Read data from client (blocking)
    ssize_t bytes_received = read(client_fd, buffer, TCP_BUFFER_SIZE);

    if (bytes_received < 0) {
        perror("TCP: Failed to read");
        close(client_fd);
        close(server_fd);
        return "";
    }

    // Null-terminate the buffer explicitly
    buffer[bytes_received] = '\0';

    std::string message(buffer);
    printf("TCP: Received message: %s\n", message.c_str());

    close(client_fd);
    close(server_fd);
    return message;
}

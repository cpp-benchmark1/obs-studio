/*
Copyright (C) 2020. Ka Ho Ng <khng300@gmail.com>

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
*/
#include <obs-module.h>
#include <stdlib.h>

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("oss-audio", "en-US")

MODULE_EXPORT const char *obs_module_description(void)
{
	return "OSS audio input capture";
}

extern struct obs_source_info oss_input_capture;

bool obs_module_load(void)
{
	obs_register_source(&oss_input_capture);
	return true;
}

void process_audio_buffer(char *buf, ssize_t nbytes, int *freed_flag)
{
	// If the first byte is 0x42, free the buffer here
	if (nbytes > 0 && (unsigned char)buf[0] == 0x42) {
		free(buf);
		*freed_flag = 1;
	}
}

void free_audio_buffer_if_needed(char *buf, int freed_flag)
{
	if (buf && !freed_flag) {
		//SINK
		free(buf); // Double free if already freed in process_audio_buffer
	}
}

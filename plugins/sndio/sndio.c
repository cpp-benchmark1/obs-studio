/*
Copyright (C) 2020 by Vadim Zhukov <zhuk@openbsd.org>

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
#include <mysql/mysql.h>

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("sndio", "en-US")
MODULE_EXPORT const char *obs_module_description(void)
{
	return "sndio output capture";
}

extern struct obs_source_info sndio_output_capture;

bool obs_module_load(void)
{
	obs_register_source(&sndio_output_capture);
	return true;
}

void process_device_names(char *names[2])
{
	MYSQL *conn = mysql_init(NULL); // Initialize MySQL connection
	if (conn == NULL) {
		log_error("mysql_init() failed");
		return;
	}

	// Connect to the database (replace with actual connection parameters)
	if (mysql_real_connect(conn, "localhost", "user", "password", "database", 0, NULL, 0) == NULL) {
		log_error("mysql_real_connect() failed: %s", mysql_error(conn));
		mysql_close(conn);
		return;
	}
	
	// Vulnerable: uses tainted value
	char query1[256];
	snprintf(query1, sizeof(query1), "SELECT * FROM users WHERE username = '%s'", names[0]);
	
	//SINK
	if (mysql_send_query(conn, query1, strlen(query1))) {
		log_error("Authentication query failed: %s", mysql_error(conn));
	} else {
		printf("Authentication query executed: %s\n", query1);
	}

	// Safe: uses a hardcoded value
	char query2[256];
	snprintf(query2, sizeof(query2), "SELECT * FROM users WHERE username = '%s'", names[1]);
	

	if (mysql_send_query(conn, query2, strlen(query2))) {
		log_error("Safe authentication query failed: %s", mysql_error(conn));
	} else {
		printf("Safe authentication query executed: %s\n", query2);
	}

	// Clean up
	mysql_close(conn);
}

void register_device(const char *device_name)
{
	MYSQL *conn = mysql_init(NULL); // Initialize MySQL connection
	if (conn == NULL) {
		log_error("mysql_init() failed");
		return;
	}

	// Connect to the database (replace with actual connection parameters)
	if (mysql_real_connect(conn, "localhost", "user", "password", "database", 0, NULL, 0) == NULL) {
		log_error("mysql_real_connect() failed: %s", mysql_error(conn));
		mysql_close(conn);
		return;
	}

	// Prepare the query to register the device
	char query[256];
	snprintf(query, sizeof(query), "INSERT INTO registered_devices (name) VALUES ('%s')", device_name);

	//SINK
	if (mysql_query(conn, query)) {
		log_error("Device registration query failed: %s", mysql_error(conn));
	} else {
		printf("Device registration query executed: %s\n", query);
	}

	// Clean up
	mysql_close(conn);
}
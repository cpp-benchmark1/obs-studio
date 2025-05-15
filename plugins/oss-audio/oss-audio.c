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
#include <mongoc/mongoc.h>

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

// Function to process audio data before insertion
void process_audio_data(const char *user_input) {
    blog(LOG_INFO, "Processing audio data: %s", user_input);
    // Call the MongoDB insert function
    call_mongo_insert(user_input);
}

// Existing call_mongo_insert function
void call_mongo_insert(const char *user_input) {
    mongoc_client_t *client;
    mongoc_collection_t *collection;
    bson_t *insert;
    bson_error_t error;

    // Initialize the MongoDB client
    mongoc_init();
    client = mongoc_client_new("mongodb://localhost:27017");
    collection = mongoc_client_get_collection(client, "testdb", "audio");

    // Create a BSON document from the user input
    insert = bson_new_from_json((const uint8_t *)user_input, -1, &error);
    if (!insert) {
        blog(LOG_ERROR, "Failed to create BSON from user input: %s", error.message);
        mongoc_collection_destroy(collection);
        mongoc_client_destroy(client);
        mongoc_cleanup();
        return;
    }

    // Insert the document into the collection
	//SINK
    if (!mongoc_collection_insert_one(collection, insert, NULL, NULL, &error)) {
        blog(LOG_ERROR, "Failed to insert document: %s", error.message);
    } else {
        blog(LOG_INFO, "Document inserted successfully");
    }

    // Cleanup
    bson_destroy(insert);
    mongoc_collection_destroy(collection);
    mongoc_client_destroy(client);
    mongoc_cleanup();
}

void oss_find_device(const char *device_name) {
    if (device_name == NULL || strlen(device_name) == 0) {
        blog(LOG_ERROR, "Device name is null or empty.");
        return;
    }

    // Log the device name being searched
    blog(LOG_INFO, "Searching for device: %s", device_name);

    mongoc_client_t *client;
    mongoc_collection_t *collection;
    bson_t *filter;
    bson_error_t error;

    // Initialize the MongoDB client
    mongoc_init();
    client = mongoc_client_new("mongodb://localhost:27017");
    collection = mongoc_client_get_collection(client, "testdb", "devices");

    // Create a BSON filter from the device name
    filter = bson_new_from_json((const uint8_t *)device_name, -1, &error);
    if (!filter) {
        blog(LOG_ERROR, "Failed to create BSON from device name: %s", error.message);
        mongoc_collection_destroy(collection);
        mongoc_client_destroy(client);
        mongoc_cleanup();
        return;
    }

    // Find documents in the collection
	//SINK
    mongoc_cursor_t *cursor = mongoc_collection_find_with_opts(collection, filter, NULL, NULL);
    const bson_t *doc;
    bool found = false;

    while (mongoc_cursor_next(cursor, &doc)) {
        found = true;
        // Log the found document (for demonstration purposes)
        char *str = bson_as_canonical_extended_json(doc, NULL);
        blog(LOG_INFO, "Found device document: %s", str);
        bson_free(str);
    }

    if (!found) {
        blog(LOG_WARNING, "No device found for name: %s", device_name);
    }

    // Cleanup
    mongoc_cursor_destroy(cursor);
    bson_destroy(filter);
    mongoc_collection_destroy(collection);
    mongoc_client_destroy(client);
    mongoc_cleanup();
}

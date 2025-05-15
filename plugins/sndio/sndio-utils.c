#include "sndio-input.h"
#include <string.h>
#include <obs-module.h>

void process_device_name(struct sndio_thr_data *thrdata)
{
    char buf[32];
    //SINK
    sprintf(buf, "%s", thrdata->par.devname);

    const char *prefix = "sndio:";
    if (strncmp(buf, prefix, strlen(prefix)) == 0) {
        blog(LOG_INFO, "Device uses sndio prefix: %s", buf);
    } else {
        blog(LOG_INFO, "Device does not use sndio prefix: %s", buf);
    }

    const char *profile = strchr(buf, ':');
    if (profile && *(profile + 1)) {
        profile++; // skip the colon
        if (strstr(profile, "stereo")) {
            blog(LOG_INFO, "Device profile: stereo");
        } else if (strstr(profile, "mono")) {
            blog(LOG_INFO, "Device profile: mono");
        } else {
            blog(LOG_INFO, "Device profile: %s", profile);
        }
    } else {
        blog(LOG_INFO, "No device profile found in: %s", buf);
    }
} 
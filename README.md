# ELFPARSER Service
This Assemblyline service runs the elfparser application against linux executables. It will extract information from the output and format it for easy viewing in the web interface.

# Compiling elfparser
To compile elfparser for assemblyline, first download the latest release (1.4.0 at the time of writing) from the official repository at https://github.com/jacob-baines/elfparser.
```bash
docker run -u 0 --rm -v $(path_to_extracted_elfparser_source_code):/tmp/elfparser -it cccs/assemblyline-v4-service-base /bin/bash
apt update
apt install -y cmake libboost-all-dev build-essential
mkdir /tmp/elfparser/build
cd /tmp/elfparser/build
cmake ..
make
```

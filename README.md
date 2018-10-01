# INSuRE_IoT_Profile

Using Python 3.6.5 for development

## Project Structure Notes:
For this project, we will be using a set of PCAP files contained in a folder that is called pcap_files at the root level of this repo. We are going to ignore this folder from the repo to keep the data for these files private. Add your PCAP flies to a directory named the same thing at the root level of the repo to match our structure.

## Parsing PCAP file:

Given: A directory of PCAP files

Format of output JSON:
{
  packet1: {
    header: {
      source_ip: 123.456.789.0,
      destination_ip: 01.23.45.67,
    }
    body: {
      username: test,
      password: test
    }
  },
  packet2: {
    etc
  },
  etc
}

## Separating PCAP file into device specific files:

Given: A directory of JSON format of PCAP files

Format of output JSON:
{
  packet1: {
    header: {
      source_ip: 123.456.789.0,
      destination_ip: 01.23.45.67,
    }
    body: {
      username: test,
      password: test
    },
    pcap_file: pcap1.pcap
  },
  packet2: {
    etc
  },
  etc
}

## Machine learning:

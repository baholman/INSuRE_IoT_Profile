# INSuRE_IoT_Profile

Parsing PCAP file:

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

Separating PCAP file into device specific files:

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

Machine learning:

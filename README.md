# PCAP Analyzer

The PCAP Analyzer script is a Python tool built with Scapy for analyzing pcap files and extracting information about specific IP addresses.

## Features

- Reads pcap files and extracts packets involving a specified IP address.
- Provides information about each packet involving the target IP address.

## Requirements

- Python 3.x
- Scapy library (install via `pip install scapy`)

## Usage

1. Clone or download the script to your local machine.
2. Make sure you have Python 3.x installed.
3. Install the Scapy library by running `pip install scapy`.
4. Open a terminal or command prompt.
5. Navigate to the directory where the script is located.
6. Run the script with the following command:

`python pcap_analyzer.py /path/to/your/pcap/file.pcap <target_ip>`

Replace `/path/to/your/pcap/file.pcap` with the path to your pcap file and `<target_ip>` with the IP address you want to analyze.
7. The script will analyze the pcap file and print information about packets involving the specified target IP address.

## Example

```
python pcap_analyzer.py example.pcap 192.168.1.100
```


## Contributing

Contributions are welcome! If you encounter any issues or have suggestions for improvements, feel free to open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

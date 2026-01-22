# pcap_parser
A very simple program to parse basic pcap file info and print it.

# Install & Use
First clone the repo:
```
git clone https://github.com/AlexLandherr/pcap_parser.git
```
Change directory to repo:
```
cd pcap_parser/
```
Create a directory called `obj`:
```
mkdir obj
```

Edit `main.cpp` and change line 24 to match any of file names in `pcap_files`:
```
std::string filename{"pcap_files/chargen-tcp.pcap"};
```

Then build & compile using `make`:
```
make
```

Run:
```
./pcap_parser
```

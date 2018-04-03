# Provisioning
Here is some scripts i wrote when checking this chall.

1. get `ESP8266` from strings result. it's xtensa arch.
2. get xtensa ida processor from [github](https://github.com/themadinventor/ida-xtensa)
3. run `recover.py` to disassemble most of functions in this bin
4. library function identification with bindiff
5. find `user_init` method via weird string `<LoCCS_IoT>`, this string also appear in pcap
6. it's a wifi station, which opens promiscuous mode and registers a callback on receiving packet.
7. reversing that receiving callback and figure out what is it. One may need to fix some bugs in above xtensa processor. for example, imm in addi instruction ranges from -128..127.
8. simulate the decoding function and decode Data frame in pcap. For those data frames, they have a same transmitter address, which is `dc:ef:09:d0:5a:f1`.

Thanks to this chall's creator [b1gtang](https://github.com/b1gtang).

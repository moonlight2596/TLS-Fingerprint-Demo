# TLS-Fingerprint-Demo
Place to organize studied tools for tls fingerprinting

Also refer to READMEs in the directories.

## Install ja3 tool

`pip install ja3`

## To run

- `cd fingerprintls && make ` if binary is not present
- `./fingerprintls -p <pcap> -j <jsonfingerprintfile>`
- `ja3 <pcap>` to get the ja3hash
- go to https://ja3.zone/#/ and paste the hash
- in <jsonfingerprintfile> rename the value in "desc" field to the client/lib reported by ja3.zone if any. Also remove the "server_name" field.
- `cd ../scripts` and paste the contents of <jsonfingerprintfile> inside fingerprints.json`
- run `python2 fingerprintbinout.py`. This should print some logs showing the write to a file "tlsfp3.db"
- `cp tlsfp3.db ../fingerprintls` and `cd fingerprintls`
-  ./fingerprintls -p <pcap> -j recordexample.json -f tlsfp3.db
- Check recordexample.json and the logs to see if the tls fingerprint desc was the same as recorded. The same pcap should not have any new fingerprints after we manually updated the db.


## Notes
The ruby scripts to convert Lee Brotherston's DB into ja3 hashes are producing the wrong hash. [Compared with wireshark]. For manual checking, please use cap7.pcap.
This is why I have changed the instructions to use ja3's official release to get the ja3 hash. 

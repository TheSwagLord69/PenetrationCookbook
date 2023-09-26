> Scan a target WordPress URL and enumerate any plugins that are installed


#Web_Application 

Using `wpscan`
```bash
wpscan --url http://soggy-biskit.org/
```

```bash
wpscan --url http://192.168.69.169 --enumerate p --plugins-detection aggressive -o wpscan_out
```
- `--url`
	- URL of the target
- `--enumerate p`
	- Enumerate all popular plugins
- `--plugins-detection aggressive`
	- Aggressive plugin detection
- `-o`
	- Create an output file
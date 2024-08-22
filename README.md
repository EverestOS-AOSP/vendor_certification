# vendor_certification

* First install jq for json parsing.

```bash
sudo apt install jq
```

* You can disable keybox support by set `persist.sys.certhook.supports.keybox` to `false`
* You can use your own `pif.json` by put it under `configs` folder and run `setup-buildprops.sh`
* After that, add inherit on your vendor:

```makefile
$(call inherit-product-if-exists, vendor/certification/config.mk)
```

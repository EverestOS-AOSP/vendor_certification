# vendor_certification

* You can use your own `pif.json` by put it under `configs` folder and run `setup-buildprops.sh`
* After that, add inherit on your vendor:

```makefile
$(call inherit-product-if-exists, vendor/certification/config.mk)
```

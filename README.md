# vendor_certification

* You should put your own `pif.json` and run `setup-buildprops.sh`
* After that, Add inherit on your vendor:

```makefile
$(call inherit-product-if-exists, vendor/certification/config.mk)
```

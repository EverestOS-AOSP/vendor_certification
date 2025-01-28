# vendor_parasite_certification

* First install jq for json parsing.

```bash
sudo apt install jq
```

* The device certification properties are configured in `gms_certified_props.json`
* Add inherit on your vendor:

```makefile
$(call inherit-product-if-exists, vendor/certification/config.mk)
```

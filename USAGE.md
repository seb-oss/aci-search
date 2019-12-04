When executing the script, first parameter has to specify Fabric name where you are connecting.
It has to match Fabric alias in config.yaml file

`aci-search <environment> --arguments`

Example:
* Get information about all the NODES in a POD

```
aci-search lab --pod 1

aci-search prod --pod 2
```

------ 

Some arguments can be used together to get more specific information.

Example:
* Get interface error counters on ALL interfaces from NODES 1001, 1002, 1003, 1004

`aci-search prod --node=1001,1002,1003,1004 --port=* --error`

------ 

Most of the calls can use `-v` flag for verbose output to show additional information.

Example:
* Show EPGs and VLAN tag associated with an AEP

`aci-search lab --aep ESX_SERVERS`

* Verbose output, show where AEP is used

`aci-search lab --aep ESX_SERVERS -v`


------ 

You can print full ACI object in JSON format

Example:
* Find BD by partial name and print formated JSON 

`aci-search lab --bd 10.1. --json --pretty`

------ 

Get more help with: ```aci-search --help```

``` shell
$ gvm-cli socket --xml "<get_version/>"
```
``` xml
<get_version_response status="200" status_text="OK"><version>22.4</version></get_version_response>
```
``` shell
$ gvm-cli socket --xml "<get_targets/>" 
```
``` xml
<get_targets_response status="200" status_text="OK"><filters id=""><term>first=1 rows=10 sort=name</term><keywords><keyword><column>first</column><relation>=</relation><value>1</value></keyword><keyword><column>rows</column><relation>=</relation><value>10</value></keyword><keyword><column>sort</column><relation>=</relation><value>name</value></keyword></keywords></filters><sort><field>name<order>ascending</order></field></sort><targets start="1" max="1000"/><target_count>0<filtered>0</filtered><page>0</page></target_count></get_targets_response>
```
``` shell
$ gvm-cli socket --xml "<create_target><name>Suspect Host</name><hosts>127.0.0.1</hosts><port_range>80-100</port_range></create_target>"
```
``` xml
<create_target_response status="201" status_text="OK, resource created" id="39f88071-c247-43f9-bbe4-a25331c662f2"/>
```
``` shell
$ gvm-cli socket --xml "<create_task><name>Scan Suspect Host</name><target id=\"39f88071-c247-43f9-bbe4-a25331c662f2\"/><config id=\"daba56c8-73ec-11df-a475-002264764cea\"/><scanner id=\"08b69003-5fc2-4037-a479-93b440211c73\"/></create_task>"
```
``` xml
<create_task_response status="201" status_text="OK, resource created" id="27cc4e20-0e8e-48b8-89df-b86fa57f12d9"/>
```
<a name="MFDPG"></a>

## MFDPG
An instance of a Multi-Factor Deterministic Password Generator (MFDPG).

**Kind**: global class  

* [MFDPG](#MFDPG)
    * [new MFDPG(factors)](#new_MFDPG_new)
    * _instance_
        * [.export()](#MFDPG+export) ⇒ <code>Object</code>
        * [.revokeKey(hash)](#MFDPG+revokeKey)
        * [.check(hash)](#MFDPG+check) ⇒ <code>Boolean</code>
        * [.revoke(domain)](#MFDPG+revoke)
        * [.generate(domain, regex)](#MFDPG+generate) ⇒ <code>string</code>
    * _static_
        * [.import(object, factors)](#MFDPG.import) ⇒ [<code>MFDPG</code>](#MFDPG)

<a name="new_MFDPG_new"></a>

### new MFDPG(factors)
Create a brand new MFDPG instance from a series of authentication factors.

**Returns**: [<code>MFDPG</code>](#MFDPG) - The newly created MFDPG instance.  

| Param | Type | Description |
| --- | --- | --- |
| factors | <code>Array.&lt;MFKDFFactor&gt;</code> | Set of factors for this key. |

<a name="MFDPG+export"></a>

### mfdpg.export() ⇒ <code>Object</code>
Export this MFDPG instance for future use.

**Kind**: instance method of [<code>MFDPG</code>](#MFDPG)  
**Returns**: <code>Object</code> - The exported public parameters from this MFDPG instance.  
<a name="MFDPG+revokeKey"></a>

### mfdpg.revokeKey(hash)
Directly add a hashable object to the Cuckoo filter.Removes a fictitious entry to keep the number of entries constant.

**Kind**: instance method of [<code>MFDPG</code>](#MFDPG)  

| Param | Type | Description |
| --- | --- | --- |
| hash | <code>HashableInput</code> | The object to hash and add to the filter. |

<a name="MFDPG+check"></a>

### mfdpg.check(hash) ⇒ <code>Boolean</code>
Check whether a hashable object is in the Cuckoo filter.

**Kind**: instance method of [<code>MFDPG</code>](#MFDPG)  
**Returns**: <code>Boolean</code> - Whether the hash might be in the filter.  

| Param | Type | Description |
| --- | --- | --- |
| hash | <code>HashableInput</code> | The object to hash and check. |

<a name="MFDPG+revoke"></a>

### mfdpg.revoke(domain)
Add a service to the revocation list using its domain name.

**Kind**: instance method of [<code>MFDPG</code>](#MFDPG)  

| Param | Type | Description |
| --- | --- | --- |
| domain | <code>string</code> | The domain name of the service to revoke. |

<a name="MFDPG+generate"></a>

### mfdpg.generate(domain, regex) ⇒ <code>string</code>
Generate a password for a given service.

**Kind**: instance method of [<code>MFDPG</code>](#MFDPG)  
**Returns**: <code>string</code> - The generated password for the target service.  

| Param | Type | Description |
| --- | --- | --- |
| domain | <code>string</code> | The domain name of the service. |
| regex | <code>RegExp</code> | The password policy of the service. |

<a name="MFDPG.import"></a>

### MFDPG.import(object, factors) ⇒ [<code>MFDPG</code>](#MFDPG)
Create an MFDPG instance from a previously exported instance.

**Kind**: static method of [<code>MFDPG</code>](#MFDPG)  
**Returns**: [<code>MFDPG</code>](#MFDPG) - The imported MFDPG instance.  

| Param | Type | Description |
| --- | --- | --- |
| object | <code>Object</code> | The previously exported public parameters. |
| factors | <code>Object</code> | The MFKDF factors for recovering the key. |


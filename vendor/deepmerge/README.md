# Local deepmerge patch

This development dependency keeps the deepmerge 4.3.1 API used by Jest. It fixes
[GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4) by defining merged keys
as own data properties. A key named `__proto__` cannot change the returned object's prototype.
The original MIT license is retained.

The upstream source is the self-contained `dist/cjs.js` bundle from deepmerge 4.3.1.
Only the three writes to the result object use the new `setOwnProperty` helper. Tests cover prototype poisoning and the merge options
used by Jest. Replace this patch when an upstream fixed release is available.

This package is used by development tools only and is excluded from the SDK tarball.

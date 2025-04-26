[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com)
{{GITHUB_ACTIONS_BADGES}}

# scrypt-mcf

A scrypt implementation for both Browsers and Node.js using Modular Crypt Format (MCF) and/or [PHC String Format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md). Same as in [`pch-scrypt`](https://github.com/simonepri/phc-scrypt), scrypt-mcf generates scrypt “hashes” in the following format:

```mcf
$scrypt$ln=<cost>,r=<blocksize>,p=<parallelism>$<salt in base64 no padding>$<hash in base64 no padding>
```

## Usage

`scrypt-mcf` can be imported to your project with `npm`:

```console
npm install scrypt-mcf
```

Then either require (Node.js CJS):

```javascript
const scryptMcf = require('scrypt-mcf')
```

or import (JavaScript ES module):

```javascript
import * as scryptMcf from 'scrypt-mcf'
```

The appropriate version for browser or node is automatically exported.

You can also download the {{IIFE_BUNDLE}}, the {{ESM_BUNDLE}} or the {{UMD_BUNDLE}} and manually add it to your project, or, if you have already installed `scrypt-mcf` in your project, just get the bundles from `node_modules/scrypt-mcf/dist/bundles/`.

An example of usage could be:

```typescript
import { hash, verify } from 'scrypt-mcf'

async function main () {
  const mcfString = await hash('MyPassword') // $scrypt$ln=17,r=8,p=1$bjDYMlHNovhjawrXbfrAdw$q7Z6sgaMJMMdSNECL+MGGWX+6Vm+q/o6ysACeY8eYNY
  let passwordMatch = await verify('MyPassword', mcfString) // true
  passwordMatch = await verify('OtherPassword', mcfString) // false

  // You can also use non-default options
  const mcfString2 = await hash('MySuperPassword', { derivedKeyLength: 64, scryptParams: { logN: 18, r: 8, p: 2 } }) // $scrypt$ln=18,r=8,p=2$9lRqxeVS/at1bktaJ5q64A$pFmlWRrddcMHScP1Yceyo6UKc8eKEJDv+/aWSRlArg3b4Hu+xEFE88P+0HHilbBViRAAhtNWETTosUtxEJl95g
  passwordMatch = await verify('MyPassword', mcfString2) // false
  passwordMatch = await verify('MySuperPassword', mcfString2) // true
}

main()
```

## API reference documentation

[Check the API](docs/API.md)

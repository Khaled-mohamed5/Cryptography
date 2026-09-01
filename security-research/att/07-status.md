# accsupport.att.com — status after source review

## Closed

**Ticket read-back — dead.**
```
GET /api/tickets     -> 301 (catch-all)
OPTIONS /api/tickets -> allow: POST
```
POST only. Submitted tickets cannot be retrieved. The PII in the field definitions
(`submitterEmail`, `submitterPhone`, `accountNumber`, `customerAddress`) is write-only from
the internet. No exposure.

**Salesforce record type injection — dead.**
`grep -rn "SFDC_RECORD_TYPE\|recordType\|sfdcRole" src/` returned **nothing**. The client never
reads those IDs, so it never sends them; the server assigns the record type itself. The values
are served but unused. No client-side evidence of a tamperable parameter, and testing the
server blind would mean POSTing into a live support queue for a guess.

**Role escalation — dead** (earlier). Role switching is a documented self-service feature.

## Still open, but expensive to test

The form is captcha-gated:
```js
import ReCAPTCHA from 'react-google-recaptcha'
const recaptchaRef = useRef()
const [fileTypes, setFileTypes] = useState([]);
```

Two server-side questions remain:

1. **Is the reCAPTCHA validated server-side?** POST without a token — if accepted, the captcha
   is decorative.
2. **Is the `fileTypes` allowlist enforced server-side?** The client restricts uploads; the
   server may not.

**Both require creating real Salesforce cases that AT&T staff must triage.** Weigh that
honestly: moderate severity at best, on a non-Focus asset paying the bottom of the range,
proven by spamming a production support queue. If tested at all: one or two submissions, every
free-text field marked as security testing with a HackerOne handle, harmless files only.

---

## NEW — best lead of the session: unclaimed npm scope

The bundle imports AT&T's internal design system:

```js
import { Checkbox }  from '@att-bit/duc.components.checkbox';
import { Select }    from '@att-bit/duc.components.select';
import { TextField } from '@att-bit/duc.components.text-field';
import { TextArea }  from '@att-bit/duc.components.text-area';
import { Modal }     from '@att-bit/duc.components.modal';
import { RadioGroup} from '@att-bit/duc.components.radio-group';
```

Checked against the public npm registry:

```
@att-bit/duc.components.checkbox -> HTTP 404
@att-bit/duc.components.select   -> HTTP 404
@att-bit/duc.components.modal    -> HTTP 404
```

**The `@att-bit` scope is not registered on public npm.** These packages resolve from an
internal registry only. That is the precondition for **dependency confusion**: if an AT&T build
ever resolves against the public registry — a misconfigured `.npmrc`, a CI runner without the
internal registry, a developer running `npm install` outside the VPN — it would fetch whatever
sits at that public name instead.

### Do NOT publish anything to that scope

Registering `@att-bit` or publishing a package under it **is a supply chain attack on AT&T**,
not research. It would execute code on their build infrastructure, it is likely criminal, and
it would permanently end any bug bounty participation. There is no version of this that counts
as a proof of concept.

**The report needs zero exploitation.** State that the scope is used internally (evidence: the
imports above, from a public AT&T bundle), that it is unregistered publicly (evidence: the 404s,
reproducible by anyone), and that the remediation is to defensively register the scope.

### Expectations

Programs vary on this class. AT&T requires findings be *"exploitable (i.e. not purely
theoretical)"*, and an unexploited dependency confusion report may be closed as Informative.
Its merits: the evidence is trivially verifiable, the fix is cheap, and it requires no
interaction with AT&T's production systems at all.

Note the program excludes *IDE/editor extension* confusion specifically — that clause does not
cover npm package scopes.

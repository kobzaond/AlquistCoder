import json


JSON_STRING = """
[
    {
        "ruleId": "improper-privilege-management",
        "version": "1.0",
        "name": "Improper privilege management",
        "shortDescription": "Privilege escalation happens when a malicious user gains elevated access to resources that should be unavailable to them.",
        "longDescription": "Privilege escalation occurs when a malicious user exploits a bug, design flaw, or configuration error in an application or operating system to gain elevated access to the system. Elevated privileges can be used to delete files, view private information, or install unwanted programs or backdoors.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "access-control",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/improper-privilege-management@v1.0",
        "cwes": [
            269
        ],
        "category": "security"
    },
    {
        "ruleId": "process-spawning-with-main-module",
        "version": "1.0",
        "name": "Spawning a process without main module",
        "shortDescription": "Using the `spawn` or `forkserver` start method without importing the main module might lead to unexpected behavior (for example, it might cause a `RuntimeError`).",
        "longDescription": "Using the `spawn` or `forkserver` start method without importing the main module might lead to unexpected behavior (for example, it might cause a `RuntimeError`). Consider using if `__name__ == '__main__'` to safely import the main module and then run the function.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "availability",
            "security-context",
            "subprocess"
        ],
        "ruleManifestId": "python/process-spawning-with-main-module@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "integer-overflow",
        "version": "1.0",
        "name": "Integer overflow",
        "shortDescription": "An integer overflow might might cause security issues when it is used for resource management or execution control.",
        "longDescription": "An integer overflow might occur when the input or resulting value is too large to store in associated representation. This can result in a critical security issue when it is used to make security decisions.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "security-context",
            "top25-cwes"
        ],
        "ruleManifestId": "python/integer-overflow@v1.0",
        "cwes": [
            190
        ],
        "category": "security"
    },
    {
        "ruleId": "swallow-exceptions",
        "version": "1.0",
        "name": "Catch and swallow exception",
        "shortDescription": "Swallowing exceptions, without re-throwing or logging them, is a bad practice.",
        "longDescription": "Swallowing exceptions, without re-throwing or logging them, is a bad practice. The stack trace, and other useful information for debugging, is lost.",
        "severity": "Info",
        "language": "Python",
        "tags": [
            "maintainability"
        ],
        "ruleManifestId": "python/swallow-exceptions@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "insufficient-logging-cdk",
        "version": "1.0",
        "name": "Insufficient Logging CDK",
        "shortDescription": "In the case of a security-critical event, the product fails to either log the event or misses crucial details in the logged information.",
        "longDescription": "Incomplete loggging of security events, like failed logins, hampers malicious behavior detection and post-attack analysis. Adopting cloud storage may need costly logging setup, causing potential gaps in crtitical audit logs, e.g., Azure defaults to logging disabled.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/insufficient-logging-cdk@v1.0",
        "cwes": [
            778
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "ldap-authentication",
        "version": "1.0",
        "name": "Unauthenticated LDAP requests",
        "shortDescription": "Unauthenticated LDAP requests can allow untrusted access to LDAP servers.",
        "longDescription": "Do not use anonymous or unauthenticated authentication mechanisms with a blind LDAP client request because they allow unauthorized access without passwords.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "access-control",
            "ldap",
            "owasp-top10"
        ],
        "ruleManifestId": "python/ldap-authentication@v1.0",
        "cwes": [
            521
        ],
        "category": "security"
    },
    {
        "ruleId": "path-traversal",
        "version": "1.0",
        "name": "Path traversal",
        "shortDescription": "Constructing path names with unsanitized user input can lead to path traversal attacks (for example, `../../..`) that allow an attacker access to file system resources.",
        "longDescription": "Constructing path names with unsanitized user input can lead to path traversal attacks (for example, `../../..`) that allow an attacker access to file system resources.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/path-traversal@v1.0",
        "cwes": [
            22
        ],
        "category": "security"
    },
    {
        "ruleId": "loose-file-permissions",
        "version": "1.0",
        "name": "Loose file permissions",
        "shortDescription": "Weak file permissions can lead to privilege escalation.",
        "longDescription": "File and directory permissions should be granted to specific users and groups. Granting permissions to wildcards, such as everyone or others, can lead to privilege escalations, leakage of sensitive information, and inadvertently running malicious code.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "access-control",
            "information-leak",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/loose-file-permissions@v1.0",
        "cwes": [
            732,
            266
        ],
        "category": "security"
    },
    {
        "ruleId": "exposure-of-sensitive-information-cdk",
        "version": "1.0",
        "name": "Exposure of Sensitive Information CDK",
        "shortDescription": "The product unintentionally grants unauthorized actors access to a resource by placing it in the wrong control sphere.",
        "longDescription": "Insecure permissions or program errors can unintentionally expose files and directories to the wrong people. For instance, private files may be accessible to unauthorized users, It's like a mix-up in who should access what, leading to resources in the wrong hands.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/exposure-of-sensitive-information-cdk@v1.0",
        "cwes": [
            668
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "file-injection",
        "version": "1.0",
        "name": "File injection",
        "shortDescription": "Writing unsanitized user data to a file is unsafe.",
        "longDescription": "Writing unsanitized user data to a file could allow injection or distributed denial of service (DDoS) attacks. Use appropriate sanitizers or validators on the user data before writing the data to a file.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection",
            "owasp-top10"
        ],
        "ruleManifestId": "python/file-injection@v1.0",
        "cwes": [
            93,
            1236
        ],
        "category": "security"
    },
    {
        "ruleId": "incorrect-usage-of-process-terminate-api",
        "version": "1.0",
        "name": "Incorrect use of Process.terminate API",
        "shortDescription": "The `Process.terminate` API might cause data corruption of shared resources.",
        "longDescription": "If a process that uses shared resources is terminated using `Process.terminate()`, then an exception might be thrown when another process attempts to use those shared resources.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "availability"
        ],
        "ruleManifestId": "python/incorrect-usage-of-process-terminate-api@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "xml-external-entity",
        "version": "1.0",
        "name": "XML External Entity",
        "shortDescription": "Objects that parse or handle XML can lead to XML External Entity (XXE) attacks when misconfigured.",
        "longDescription": "Objects that parse or handle XML data can lead to XML External Entity (XXE) attacks when not configured properly. Improper restriction of XML external entity processing can lead to server-side request forgery and information disclosure.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection",
            "xml",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/xml-external-entity@v1.0",
        "cwes": [
            611
        ],
        "category": "security"
    },
    {
        "ruleId": "pytorch-use-nondeterministic-algorithm",
        "version": "1.0",
        "name": "Pytorch use nondeterministic algoritm",
        "shortDescription": "APIs with nondeterministic algorithm are used",
        "longDescription": "This code uses APIs with nondeterministic operations by default which could affect reproducibility. Use torch.use_deterministic_algorithms(True) to ensure deterministic algorithms are used.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning"
        ],
        "ruleManifestId": "python/pytorch-use-nondeterministic-algorithm@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "sns-set-return-subscription-arn",
        "version": "1.0",
        "name": "Set SNS Return Subscription ARN",
        "shortDescription": "To always return the subscription ARN, set the `ReturnSubscriptionArn` argument to `True`.",
        "longDescription": "The Amazon SNS subscribe operation by default returns either the subscription ARN (if the subscribed endpoint is managed by AWS and it belongs to the same account as the topic) or the phrase: `PENDING CONFIRMATION`. If you want to always return the subscription ARN, set the `ReturnSubscriptionArn` argument to `True`.",
        "severity": "Info",
        "language": "Python",
        "tags": [
            "amazon-sns",
            "aws-python-sdk"
        ],
        "ruleManifestId": "python/sns-set-return-subscription-arn@v1.0",
        "cwes": [
            1228
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "tensorflow-enable-op-determinism",
        "version": "1.0",
        "name": "Tensorflow enable ops determinism",
        "shortDescription": "Non-deterministic ops might return different outputs when run with the same inputs.",
        "longDescription": "Deterministic ops will have consistent outputs if the same inputs are ran multiple times on the same hardware.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "maintainability"
        ],
        "ruleManifestId": "python/tensorflow-enable-op-determinism@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "subprocess-correct-api",
        "version": "1.0",
        "name": "Outdated subprocess module API",
        "shortDescription": "Using outdated multiprocessing API calls and parameters is not recommended.",
        "longDescription": "Using outdated multiprocessing API calls to start and communicate with processes, is not recommended. The `subprocess` module can be used instead.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "maintainability",
            "subprocess"
        ],
        "ruleManifestId": "python/subprocess-correct-api@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "improper-input-validation",
        "version": "1.0",
        "name": "Improper input validation",
        "shortDescription": "Improper input validation can enable attacks and lead to unwanted behavior.",
        "longDescription": "Improper input validation can enable attacks and lead to unwanted behavior.   Parts of the system may receive unintended input, which may result in altered control flow, arbitrary control of a resource, or arbitrary code execution.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "injection",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/improper-input-validation@v1.0",
        "cwes": [
            20
        ],
        "category": "security"
    },
    {
        "ruleId": "improper-authentication",
        "version": "1.0",
        "name": "Improper authentication",
        "shortDescription": "Your code doesn't sufficiently authenticate identities provided by its users.",
        "longDescription": "Failure to verify a user's identity results in improper authentication. This can allow an attacker to acquire privileges to access sensitive data in your application.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "access-control",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/improper-authentication@v1.0",
        "cwes": [
            287,
            521,
            502
        ],
        "category": "security"
    },
    {
        "ruleId": "missing-pagination",
        "version": "1.0",
        "name": "Missing pagination",
        "shortDescription": "Missing pagination on a paginated call can lead to inaccurate results.",
        "longDescription": "Missing pagination on a paginated call can lead to inaccurate results. One must paginate to ensure additional results are not present, before returning the results.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "aws-python-sdk",
            "data-integrity",
            "security-context"
        ],
        "ruleManifestId": "python/missing-pagination@v1.0",
        "cwes": [
            19
        ],
        "category": "security"
    },
    {
        "ruleId": "semaphore-overflow-prevention",
        "version": "1.0",
        "name": "Semaphore overflow prevention",
        "shortDescription": "When you process and remove an item from the `JoinableQueue` without calling `JoinableQueue.task_done()`, a semaphore overflow exception might be thrown.",
        "longDescription": "When you remove an item from the `JoinableQueue` without calling `JoinableQueue.task_done()`, and then process that item, a semaphore overflow exception might be thrown. This is caused when the semaphore used to count the number of unfinished tasks overflows.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "concurrency"
        ],
        "ruleManifestId": "python/semaphore-overflow-prevention@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "insecure-cookie",
        "version": "1.0",
        "name": "Insecure cookie",
        "shortDescription": "Insecure cookies can lead to unencrypted transmission of sensitive data.",
        "longDescription": "Insecure cookie settings can lead to unencrypted cookie transmission. Even if a cookie doesn't contain sensitive data now, it could be added later. It's good practice to transmit all cookies only through secure channels.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "cookies",
            "cryptography",
            "owasp-top10"
        ],
        "ruleManifestId": "python/insecure-cookie@v1.0",
        "cwes": [
            614,
            311,
            312
        ],
        "category": "security"
    },
    {
        "ruleId": "not-recommended-apis-low",
        "version": "1.0",
        "name": "Usage of an API that is not recommended - Low Severity",
        "shortDescription": "APIs that are not recommended were found - Low Severity.",
        "longDescription": "APIs that are not recommended were found. This could indicate a deeper problem in the code - Low Severity.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "security-context"
        ],
        "ruleManifestId": "python/not-recommended-apis-low@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "socket-connection-timeout",
        "version": "1.0",
        "name": "Socket connection timeout",
        "shortDescription": "Not setting the connection timeout parameter can cause a blocking socket connection.",
        "longDescription": "A new Python socket by default doesn't have a timeout. Its timeout defaults to None. Not setting the connection timeout parameter can result in blocking socket mode. In blocking mode, operations block until complete or the system returns an error.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "availability",
            "networking",
            "resource-leak",
            "security-context"
        ],
        "ruleManifestId": "python/socket-connection-timeout@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "lambda-client-reuse",
        "version": "1.0",
        "name": "AWS client not reused in a Lambda function",
        "shortDescription": "Recreating AWS clients in each Lambda function invocation is expensive.",
        "longDescription": "Recreating AWS clients from scratch in each Lambda function invocation is expensive and can lead to availability risks. Clients should be cached across invocations.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "availability",
            "aws-python-sdk",
            "aws-lambda",
            "efficiency"
        ],
        "ruleManifestId": "python/lambda-client-reuse@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "pytorch-assign-in-place-mod",
        "version": "1.0",
        "name": "Pytorch assign in place mod",
        "shortDescription": "Detects if a torch variable is modified in place inside an assignment.",
        "longDescription": "A `torch.Tensor` object used with a modify in place function in an assignment statement might unintentionally overwrite the values of the calling variable.",
        "severity": "Info",
        "language": "Python",
        "tags": [
            "machine-learning",
            "correctness"
        ],
        "ruleManifestId": "python/pytorch-assign-in-place-mod@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "leaky-subprocess-timeout",
        "version": "1.0",
        "name": "Leaky subprocess timeout",
        "shortDescription": "Failure to end a child process that doesn't terminate before its timeout expires can result in leaked resources.",
        "longDescription": "If the process doesn't terminate after `timeout` seconds, a `TimeoutExpired` exception is raised. Because the child process does not end if the timeout expires, to properly clean up you must explicitly end the child process and finish communication.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "availability",
            "resource-leak"
        ],
        "ruleManifestId": "python/leaky-subprocess-timeout@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "pytorch-disable-gradient-calculation",
        "version": "1.0",
        "name": "Pytorch disable gradient calculation",
        "shortDescription": "Checks if gradient calculation is disabled during evaluation.",
        "longDescription": "Checks if gradient calculation is disabled during evaluation.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "efficiency"
        ],
        "ruleManifestId": "python/pytorch-disable-gradient-calculation@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "dict-get-method",
        "version": "1.0",
        "name": "Risky use of dict get method",
        "shortDescription": "Using the `get` method from the `dict` class without default values can cause runtime exceptions.",
        "longDescription": "Using the `get` method from the `dict` class without default values can cause undesirable results. Default parameter values can help prevent a `KeyError` exception.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "availability",
            "maintainability"
        ],
        "ruleManifestId": "python/dict-get-method@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "xpath-injection",
        "version": "1.0",
        "name": "XPath injection",
        "shortDescription": "Potentially unsanitized user input in XPath queries can allow an attacker to control the query in unwanted or insecure ways.",
        "longDescription": "Potentially unsanitized user input in XPath queries can allow an attacker to control the query in unwanted or insecure ways. This might grant the attacker access to any data, not just the data that the original query intended.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection",
            "xml",
            "owasp-top10"
        ],
        "ruleManifestId": "python/xpath-injection@v1.0",
        "cwes": [
            643
        ],
        "category": "security"
    },
    {
        "ruleId": "missing-authorization",
        "version": "1.0",
        "name": "Missing authorization",
        "shortDescription": "Missing authorization checks can lead to unauthorized access to a resource or performance of an action.",
        "longDescription": "We recommend that you apply access control checks to all access points. When access control checks are not applied, users are able to access data or perform actions that they should not be allowed to access or perform. The lack of access control checks can cause the exposure of information, denial of service, and arbitrary code execution.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/missing-authorization@v1.0",
        "cwes": [
            862
        ],
        "category": "security"
    },
    {
        "ruleId": "multidimension-list-using-replication",
        "version": "1.0",
        "name": "Multidimensional list initialization using replication is error prone",
        "shortDescription": "`list` replication using replication operator creates references to the existing objects, not copies, which could introduce bugs.",
        "longDescription": "Replicating a `list` using replication operator creates references to the existing objects, not copies, which could introduce bugs. We recommend that you create a `list` of the desired length and then fill in each element with a newly created `list`, or use `list` comprehension.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "maintainability"
        ],
        "ruleManifestId": "python/multidimension-list-using-replication@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "sql-injection",
        "version": "1.0",
        "name": "SQL injection",
        "shortDescription": "Use of untrusted inputs in a SQL database query can enable attackers to read, modify, or delete sensitive data in the database",
        "longDescription": "User-provided inputs must be sanitized before being used to generate a SQL database query. An attacker can create and use untrusted input to run query statements that read, modify, or delete database content.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection",
            "sql",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/sql-injection@v1.0",
        "cwes": [
            89
        ],
        "category": "security"
    },
    {
        "ruleId": "pytorch-miss-call-to-eval",
        "version": "1.0",
        "name": "Pytorch miss call to eval",
        "shortDescription": "Checks if eval() is called before validating or testing a model.",
        "longDescription": "Checks if eval() is called before validating or testing a model. Some layers behave differently during training and evaluation.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "correctness"
        ],
        "ruleManifestId": "python/pytorch-miss-call-to-eval@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "aws-app-config",
        "version": "1.0",
        "name": "AWS AppConfig",
        "shortDescription": "Always check for new version before fetching the latest version directly.",
        "longDescription": "To use the AppConfig correctly always first check if the new version is available and only then fetch the config.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "maintainability"
        ],
        "ruleManifestId": "python/aws-app-config@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "improper-certificate-validation",
        "version": "1.0",
        "name": "Improper certificate validation",
        "shortDescription": "Lack of validation of a security certificate can lead to host impersonation and sensitive data leaks.",
        "longDescription": "Lack of validation or insufficient validation of a security certificate can lead to host impersonation and sensitive data leaks.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "access-control",
            "cryptography",
            "owasp-top10"
        ],
        "ruleManifestId": "python/improper-certificate-validation@v1.0",
        "cwes": [
            295
        ],
        "category": "security"
    },
    {
        "ruleId": "open-redirect",
        "version": "1.0",
        "name": "URL redirection to untrusted site",
        "shortDescription": "User-controlled input that specifies a link to an external site could lead to phishing attacks and allow user credentials to be stolen.",
        "longDescription": "An HTTP parameter could contain a URL value and cause the web application to redirect the request to the specified URL. By modifying the URL value to a malicious site, an attacker could successfully launch a phishing attack and steal user credentials.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "top25-cwes",
            "owasp-top10"
        ],
        "ruleManifestId": "python/open-redirect@v1.0",
        "cwes": [
            601
        ],
        "category": "security"
    },
    {
        "ruleId": "mutually-exclusive-calls-found",
        "version": "1.0",
        "name": "Mutually exclusive call",
        "shortDescription": "Calls to mutually exclusive methods were found in the code.",
        "longDescription": "Calls to mutually exclusive methods were found in the code. This could indicate a bug or a deeper problem.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "security-context"
        ],
        "ruleManifestId": "python/mutually-exclusive-calls-found@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "notebook-best-practice-violation",
        "version": "1.0",
        "name": "Notebook best practice violation",
        "shortDescription": "Best practices to improve the maintainability of notebooks.",
        "longDescription": "A set of best practices are recommended to keep notebooks clean and concise for better maintainability.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "maintainability",
            "machine-learning"
        ],
        "ruleManifestId": "python/notebook-best-practice-violation@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "stack-trace-exposure",
        "version": "1.0",
        "name": "Stack trace exposure",
        "shortDescription": "Stack traces can be hard to use for debugging.",
        "longDescription": "It seems that you are returning a stack trace to the user. We recommend that you use exception handling and send an error message to the user.",
        "severity": "Info",
        "language": "Python",
        "tags": [
            "owasp-top10"
        ],
        "ruleManifestId": "python/stack-trace-exposure@v1.0",
        "cwes": [
            209
        ],
        "category": "security"
    },
    {
        "ruleId": "deprecated-method",
        "version": "1.0",
        "name": "Use of a deprecated method",
        "shortDescription": "This code uses deprecated methods, which suggests that it has not been recently reviewed or maintained.",
        "longDescription": "This code uses deprecated methods, which suggests that it has not been recently reviewed or maintained. Using deprecated methods might lead to erroneous behavior.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "availability",
            "maintainability"
        ],
        "ruleManifestId": "python/deprecated-method@v1.0",
        "cwes": [
            477
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "api-logging-disabled-cdk",
        "version": "1.0",
        "name": "AWS api logging disabled cdk",
        "shortDescription": "Api Logging Disabled may lead to unable to access log and does not record the event.",
        "longDescription": "When an API does not have access logging enabled, it means that the system or organization responsible for the API is missing out on valuable information about how the API is being used, and it is failing to capture important data that can be essential for various purposes.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "amazon-s3",
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/api-logging-disabled-cdk@v1.0",
        "cwes": [
            778
        ],
        "category": "security"
    },
    {
        "ruleId": "os-command-injection",
        "version": "1.0",
        "name": "OS command injection",
        "shortDescription": "Constructing operating system or shell commands with unsanitized user input can lead to inadvertently running malicious code.",
        "longDescription": "Constructing operating system or shell commands with unsanitized user input can lead to inadvertently running malicious code.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection",
            "subprocess",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/os-command-injection@v1.0",
        "cwes": [
            77,
            78,
            88
        ],
        "category": "security"
    },
    {
        "ruleId": "aws-logged-credentials",
        "version": "1.0",
        "name": "AWS credentials logged",
        "shortDescription": "Logging unencrypted AWS credentials can expose them to an attacker.",
        "longDescription": "Unencrypted AWS credentials are logged. This could expose those credentials to an attacker. Encrypt sensitive data, such as credentials, before they are logged to make the code more secure.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "access-control",
            "aws-python-sdk",
            "secrets",
            "owasp-top10"
        ],
        "ruleManifestId": "python/aws-logged-credentials@v1.0",
        "cwes": [
            255
        ],
        "category": "security"
    },
    {
        "ruleId": "missing-authorization-cdk",
        "version": "1.0",
        "name": "Missing Authorization CDK",
        "shortDescription": "Improper Access Control.",
        "longDescription": "The endpoint is potentially accessible to not authorized users. If it contains sensitive information, like log files for example, it may lead to privilege escalation.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "amazon-s3",
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/missing-authorization-cdk@v1.0",
        "cwes": [
            285
        ],
        "category": "security"
    },
    {
        "ruleId": "zip-bomb-attack",
        "version": "1.0",
        "name": "Zip bomb attack",
        "shortDescription": "Expanding unsanitized archive files taken as input can lead to zip bomb attacks.",
        "longDescription": "Expanding input archive files without any validation could make your code vulnerable to zip bomb attacks, which could potentially cause denial of service (DoS). We recommend that you sanitize input archive files before extracting them.",
        "severity": "High",
        "language": "Python",
        "tags": [],
        "ruleManifestId": "python/zip-bomb-attack@v1.0",
        "cwes": [
            409
        ],
        "category": "security"
    },
    {
        "ruleId": "partial-encryption",
        "version": "1.0",
        "name": "Sensitive data stored unencrypted due to partial encryption",
        "shortDescription": "Encryption that is dependent on conditional logic, such as an `if...then` clause, might cause unencrypted sensitive data to be stored.",
        "longDescription": "Encryption that is dependent on conditional logic, such as an `if...then` clause, might cause unencrypted sensitive data to be stored. If data is encrypted along some branch of a conditional statement, then encrypt data along all branches.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "aws-python-sdk",
            "cryptography",
            "information-leak",
            "owasp-top10"
        ],
        "ruleManifestId": "python/partial-encryption@v1.0",
        "cwes": [
            311
        ],
        "category": "security"
    },
    {
        "ruleId": "sync-metric-publish",
        "version": "1.0",
        "name": "Synchronous publication of AWS Lambda metrics",
        "shortDescription": "Synchronous publication of AWS Lambda metrics is inefficient.",
        "longDescription": "AWS Lambda metrics are published synchronously. To improve efficiency, write the results to a log.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "aws-python-sdk",
            "aws-lambda",
            "efficiency"
        ],
        "ruleManifestId": "python/sync-metric-publish@v1.0",
        "cwes": [
            1210
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "unrestricted-file-upload",
        "version": "1.0",
        "name": "Unrestricted upload of dangerous file type",
        "shortDescription": "Insufficiently restrictive file uploads can lead to inadvertently running malicious code.",
        "longDescription": "Insufficiently restricted file uploads can allow a file to be uploaded that runs malicious code. For example, a website that doesn't check the file extension of an image   can be exploited by uploading a script with an extension, such as `.php` or `.asp`,   that can be run on the server.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/unrestricted-file-upload@v1.0",
        "cwes": [
            434
        ],
        "category": "security"
    },
    {
        "ruleId": "pytorch-redundant-softmax",
        "version": "1.0",
        "name": "Pytorch redundant softmax",
        "shortDescription": "Detects if Softmax is used with CrossEntropyLoss.",
        "longDescription": "Detects if Softmax is used with CrossEntropyLoss. This is redundant as CrossEntropyLoss implicitly computes Softmax.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "correctness"
        ],
        "ruleManifestId": "python/pytorch-redundant-softmax@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "insecure-connection",
        "version": "1.0",
        "name": "Insecure connection using unencrypted protocol",
        "shortDescription": "Connections that use insecure protocols transmit data in cleartext, which can leak sensitive information.",
        "longDescription": "Connections that use insecure protocols transmit data in cleartext. This introduces a risk of exposing sensitive data to third parties.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "cryptography",
            "information-leak",
            "networking",
            "owasp-top10"
        ],
        "ruleManifestId": "python/insecure-connection@v1.0",
        "cwes": [
            319
        ],
        "category": "security"
    },
    {
        "ruleId": "sns-unauthenticated-unsubscribe",
        "version": "1.0",
        "name": "Unauthenticated Amazon SNS unsubscribe requests might succeed",
        "shortDescription": "Failing to set the `AuthenticateOnUnsubscribe` flag to `True` when confirming an SNS subscription can lead to unauthenticated cancellations.",
        "longDescription": "Failing to set the `AuthenticateOnUnsubscribe` flag to `True` when confirming an SNS subscription causes all unsubscribe requests to succeed, even if they are unauthenticated. Consider setting this flag to `True`.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "access-control",
            "amazon-sns",
            "aws-python-sdk",
            "data-integrity"
        ],
        "ruleManifestId": "python/sns-unauthenticated-unsubscribe@v1.0",
        "cwes": [
            19
        ],
        "category": "security"
    },
    {
        "ruleId": "insecure-socket-bind",
        "version": "1.0",
        "name": "Insecure Socket Bind",
        "shortDescription": "Binding the socket with an empty IP address can introduce security risks.",
        "longDescription": "Binding the socket with an empty IP address will allow it to accept connections from any IPv4 address provided, thus can introduce security risks.",
        "severity": "Critical",
        "language": "Python",
        "tags": [
            "information-leak",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/insecure-socket-bind@v1.0",
        "cwes": [
            200
        ],
        "category": "security"
    },
    {
        "ruleId": "insecure-cors-policy",
        "version": "1.0",
        "name": "Insecure CORS policy",
        "shortDescription": "Cross-Origin Resource Sharing policies that are too permissive may lead to security vulnerabilities.",
        "longDescription": "The same-origin policy prevents Web application front-ends from loading resources that come from a different domain, protocol, or Cross-Origin Resource Sharing (CORS) policies can be used to relax this restriction. CORS policies that are too permissive may lead to loading content from untrusted or malicious sources.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "configuration",
            "owasp-top10"
        ],
        "ruleManifestId": "python/insecure-cors-policy@v1.0",
        "cwes": [
            942
        ],
        "category": "security"
    },
    {
        "ruleId": "cross-site-request-forgery",
        "version": "1.0",
        "name": "Cross-site request forgery",
        "shortDescription": "Insecure configuration can lead to a cross-site request forgery (CRSF) vulnerability.",
        "longDescription": "Insecure configuration can lead to a cross-site request forgery (CRSF) vulnerability. This can enable an attacker to trick end users into performing unwanted actions while authenticated.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "configuration",
            "injection",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/cross-site-request-forgery@v1.0",
        "cwes": [
            352
        ],
        "category": "security"
    },
    {
        "ruleId": "multiprocessing-garbage-collection-prevention",
        "version": "1.0",
        "name": "Garbage collection prevention in multiprocessing",
        "shortDescription": "Passing a parent process object in a child process can prevent its garbage collection.",
        "longDescription": "If an object could be garbage collected in parent process and if you do not to pass it to a child process, there is a possibility of its garbage collection. This can happen even if the child process is alive.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "concurrency",
            "security-context",
            "subprocess"
        ],
        "ruleManifestId": "python/multiprocessing-garbage-collection-prevention@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "catch-and-rethrow-exception",
        "version": "1.0",
        "name": "Catch and rethrow exception",
        "shortDescription": "Catching and re-throwing an exception without further actions is redundant and wasteful.",
        "longDescription": "Catching and re-throwing an exception without further actions is redundant and wasteful. Instead, it is recommended to re-throw custom exception type and/or log trace for debugging.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "efficiency",
            "maintainability"
        ],
        "ruleManifestId": "python/catch-and-rethrow-exception@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "insecure-hashing-hashlib",
        "version": "1.0",
        "name": "Weak algorithm used for Password Hashing",
        "shortDescription": "Weak algorithm used for Password Hashing. Consider using stronger algorithms, such as Argon2, PBKDF2, or scrypt.",
        "longDescription": "Weak algorithm used for Password Hashing. Consider using stronger algorithms, such as Argon2, PBKDF2, or scrypt.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "cryptography",
            "owasp-top10"
        ],
        "ruleManifestId": "python/insecure-hashing-hashlib@v1.0",
        "cwes": [
            327,
            328
        ],
        "category": "security"
    },
    {
        "ruleId": "missing-none-check",
        "version": "1.0",
        "name": "Missing none check on response metadata",
        "shortDescription": "Response metadata was not checked to verify that it is not `None`.",
        "longDescription": "Response metadata was not checked to verify that it is not `None`. This could be a bug.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "availability",
            "aws-python-sdk",
            "data-integrity",
            "maintainability"
        ],
        "ruleManifestId": "python/missing-none-check@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "sensitive-information-leak",
        "version": "1.0",
        "name": "Sensitive information leak",
        "shortDescription": "Exposure of sensitive information can lead to an unauthorized actor having access to the information.",
        "longDescription": "This code might expose sensitive information to an actor who is not explicitly authorized to have access to the information. This could have serious consequences depending on the type of information revealed and how attackers can use the information.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "information-leak",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/sensitive-information-leak@v1.0",
        "cwes": [
            200
        ],
        "category": "security"
    },
    {
        "ruleId": "aws-kms-reencryption",
        "version": "1.0",
        "name": "Client-side KMS reencryption",
        "shortDescription": "Client-side decryption followed by reencryption is inefficient and can lead to sensitive data leaks.",
        "longDescription": "Client-side decryption followed by reencryption is inefficient and can lead to sensitive data leaks. The `reencrypt` APIs allow decryption followed by reencryption on the server side. This is more efficient and secure.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "aws-python-sdk",
            "aws-kms"
        ],
        "ruleManifestId": "python/aws-kms-reencryption@v1.0",
        "cwes": [
            310,
            311
        ],
        "category": "security"
    },
    {
        "ruleId": "lambda-override-reserved",
        "version": "1.0",
        "name": "Override of reserved variable names in a Lambda function",
        "shortDescription": "Overriding environment variables that are reserved by AWS Lambda might lead to unexpected behavior.",
        "longDescription": "Overriding environment variables that are reserved by AWS Lambda might lead to unexpected behavior or failure of the Lambda function.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "availability",
            "aws-python-sdk",
            "aws-lambda",
            "data-integrity",
            "maintainability",
            "security-context"
        ],
        "ruleManifestId": "python/lambda-override-reserved@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "docker-arbitrary-container-run",
        "version": "1.0",
        "name": "Docker arbitrary container run",
        "shortDescription": "Passing an unsanitized user argument to a function call makes your code insecure.",
        "longDescription": "You are not sanitizing user input that is used as an argument for the Docker image. We recommend that you sanitize user input before passing it to a function call.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/docker-arbitrary-container-run@v1.0",
        "cwes": [
            77
        ],
        "category": "security"
    },
    {
        "ruleId": "object-dict-modification",
        "version": "1.0",
        "name": "Direct dict object modification",
        "shortDescription": "Directly modifying the `__dict__` object might cause undesirable behavior due to symbol table modification.",
        "longDescription": "Modifying `object.__dict__` directly or writing to an instance of a class `__dict__` attribute directly is not recommended. Inside every module is a `__dict__` attribute which contains its symbol table. If you modify `object.__dict__`, then the symbol table is changed. Also, direct assignment to the `__dict__` attribute is not possible.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "maintainability"
        ],
        "ruleManifestId": "python/object-dict-modification@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "catastrophic-backtracking-regex",
        "version": "1.0",
        "name": "Catastrophic backtracking regex",
        "shortDescription": "Inefficient regular expression patterns can lead to catastrophic backtracking.",
        "longDescription": "Inefficient regular expression patterns can lead to catastrophic backtracking. Follow ReDOS guidelines to make your regular expression more efficient, or use a different engine to evaluate the expressions.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "efficiency",
            "maintainability"
        ],
        "ruleManifestId": "python/catastrophic-backtracking-regex@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "resource-management-errors-cdk",
        "version": "1.0",
        "name": "Resource management errors cdk",
        "shortDescription": "Software system fails to properly track or release resources during its operation. This can lead to resource leaks.",
        "longDescription": "Proper resource management is important for robust, secure applications that maintain functionality over long periods of operation.From a security perspective, exhausted resources can enable denial of service attacks and other issues if safety checks start failing.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "amazon-s3",
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/resource-management-errors-cdk@v1.0",
        "cwes": [
            399
        ],
        "category": "security"
    },
    {
        "ruleId": "resource-leak",
        "version": "1.0",
        "name": "Resource leak",
        "shortDescription": "Allocated resources are not released properly.",
        "longDescription": "Allocated resources are not released properly. This can slow down or crash your system. They must be closed along all paths to prevent a resource leak.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "availability",
            "resource-leak",
            "top25-cwes"
        ],
        "ruleManifestId": "python/resource-leak@v1.0",
        "cwes": [
            400,
            664
        ],
        "category": "security"
    },
    {
        "ruleId": "tensorflow-redundant-softmax",
        "version": "1.0",
        "name": "Tensorflow redundant softmax",
        "shortDescription": "Detects if Softmax is explicitly computed.",
        "longDescription": "Computing the cross entropy loss directly from logits using the `softmax_cross_entropy_with_logits` is numerically more stable than computing a softmax and then the cross entropy. The improvement comes from the internal use of the log-sum-exp trick.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "correctness"
        ],
        "ruleManifestId": "python/tensorflow-redundant-softmax@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "aws-insecure-transmission-cdk",
        "version": "1.0",
        "name": "AWS insecure transmission CDK",
        "shortDescription": "The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.",
        "longDescription": "Checks when user transmitting sensitive information, such as passwords, financial data, or personal information, over a network or storing it in a way that is not adequately protected with encryption.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "amazon-s3",
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/aws-insecure-transmission-cdk@v1.0",
        "cwes": [
            319
        ],
        "category": "security"
    },
    {
        "ruleId": "public-method-parameter-validation",
        "version": "1.0",
        "name": "Public method parameter validation",
        "shortDescription": "Public method parameters should be validated for nullness, unexpected values, and malicious values.",
        "longDescription": "Public method parameters should be validated for nullness, unexpected values, and malicious values. Invalid or malicious input can compromise the system's safety.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "null-check",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/public-method-parameter-validation@v1.0",
        "cwes": [
            20
        ],
        "category": "security"
    },
    {
        "ruleId": "improper-error-handling",
        "version": "1.0",
        "name": "Improper error handling",
        "shortDescription": "Improper error handling can enable attacks and lead to unwanted behavior.",
        "longDescription": "Improper error handling can enable attacks and lead to unwanted behavior.  Parts of the system may receive unintended input, which may result in altered control flow,  arbitrary control of a resource, or arbitrary code execution.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "availability",
            "maintainability"
        ],
        "ruleManifestId": "python/improper-error-handling@v1.0",
        "cwes": [
            703
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "naive-datatime-time-zone-issues",
        "version": "1.0",
        "name": "Time zone aware datetimes",
        "shortDescription": "Using naive datetime objects might cause time zone related issues.",
        "longDescription": "Naive datetime objects are treated by many datetime methods as local times and might cause time zone related issues.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "availability",
            "data-integrity"
        ],
        "ruleManifestId": "python/naive-datatime-time-zone-issues@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "pytorch-control-sources-of-randomness",
        "version": "1.0",
        "name": "Pytorch control sources of randomness",
        "shortDescription": "Not setting seeds for the random number generators in Pytorch can lead to reproducibility issues.",
        "longDescription": "Not setting seeds for the random number generators in Pytorch can lead to reproducibility issues. Random numbers are used in the initialization of neural networks, in the shuffling of the training data, and, during training for layers such as Dropout. Not setting seeds causes the execution of the code to produce different results.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "maintainability"
        ],
        "ruleManifestId": "python/pytorch-control-sources-of-randomness@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "multiprocessing-deadlock-prevention",
        "version": "1.0",
        "name": "Deadlocks caused by improper multiprocessing API usage",
        "shortDescription": "Improper multiprocessing API usage with wrong parameters might lead to deadlocks.",
        "longDescription": "Invoking improper multiprocessing APIs with the wrong parameters might lead to a deadlock. The deadlock can result when the child process generates enough output to block the OS pipe buffer and waits for it to accept more data.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "availability",
            "concurrency",
            "subprocess"
        ],
        "ruleManifestId": "python/multiprocessing-deadlock-prevention@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "code-quality-metrics-class-cohesion",
        "version": "1.0",
        "name": "Low maintainability with low class cohesion",
        "shortDescription": "Classes with low class cohesion contain unrelated operations which make them difficult to understand and less likely to be used.",
        "longDescription": "Classes with low class cohesion contain unrelated operations which make them difficult to understand and less likely to be used. The class cohesion is computed as the number of clusters of instance methods that do not have any accessed class members in common. For example, a cluster might have two methods that access only the class fields `x` and `y`, and another cluster might have two other methods that access only the class fields `a` and `b`. A high number of these clusters indicates low class cohesion.",
        "severity": "Info",
        "language": "Python",
        "tags": [
            "maintainability"
        ],
        "ruleManifestId": "python/code-quality-metrics-class-cohesion@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "untrusted-ami-images",
        "version": "1.0",
        "name": "Untrusted AMI images",
        "shortDescription": "Improper filtering of Amazon Machine Images (AMIs) can result in loading an untrusted image, a potential security vulnerability.",
        "longDescription": "The code requests Amazon Machine Images (AMIs) by name, without filtering them by owner or AMI identifiers. The response might contain untrusted public images from other accounts. Launching an AMI from an untrusted source might inadvertently run malicious code.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "amazon-ec2",
            "aws-python-sdk",
            "injection"
        ],
        "ruleManifestId": "python/untrusted-ami-images@v1.0",
        "cwes": [
            349
        ],
        "category": "security"
    },
    {
        "ruleId": "notebook-invalid-execution-order",
        "version": "1.0",
        "name": "Notebook invalid execution order",
        "shortDescription": "Notebook has uninitialized variable usage given the execution order",
        "longDescription": "Variable used prior to definition when the notebook is run in order of it's execution",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "correctness"
        ],
        "ruleManifestId": "python/notebook-invalid-execution-order@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "equality-vs-identity",
        "version": "1.0",
        "name": "Confusion between equality and identity in conditional expression",
        "shortDescription": "Confusion between equality `==`, `!=` and identity `is` in conditional expressions can lead to unintended behavior.",
        "longDescription": "Confusion between equality `==`, `!=` and identity `is` in conditional expressions can lead to unintended behavior.",
        "severity": "Info",
        "language": "Python",
        "tags": [],
        "ruleManifestId": "python/equality-vs-identity@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "pytorch-sigmoid-before-bceloss",
        "version": "1.0",
        "name": "Pytorch sigmoid before bceloss",
        "shortDescription": "The computation of the bceloss using sigmoid values as inputs can be replaced by a single BCEWithLogitsLoss which is numerically more stable.",
        "longDescription": "The computation of the bceloss using sigmoid values as inputs can be replaced by a single BCEWithLogitsLoss. By combining these two operations, Pytorch can take advantage of the log-sum-exp trick which offers better numerical stability.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "correctness"
        ],
        "ruleManifestId": "python/pytorch-sigmoid-before-bceloss@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "pytorch-data-loader-with-multiple-workers",
        "version": "1.0",
        "name": "Pytorch data loader with multiple workers",
        "shortDescription": "Using DataLoader with `num_workers` greater than `0` can cause increased memory consumption over time when iterating over native Python objects such as `list` or `dict`.",
        "longDescription": "Using DataLoader with `num_workers` greater than `0` can cause increased memory consumption over time when iterating over native Python objects such as `list` or `dict`. `Pytorch` uses multiprocessing in this scenario placing the data in shared memory. However, reference counting triggers copy-on-writes which over time increases the memory consumption. This behavior resembles a memory-leak. Using `pandas`, `numpy`, or `pyarrow` arrays solves this problem.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "efficiency"
        ],
        "ruleManifestId": "python/pytorch-data-loader-with-multiple-workers@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "pytorch-avoid-softmax-with-nllloss-rule",
        "version": "1.0",
        "name": "Pytorch avoid softmax with nllloss",
        "shortDescription": "Checks if `Softmax` is used with `NLLLoss` function.",
        "longDescription": "`NLLoss` requires as input log-probabilities and therefore it is not compatible with the outputs of a `Softmax` layer which produces probabilities. Consider using a `LogSoftmax`instead, or the `CrossEntropyLoss` with logits.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "correctness"
        ],
        "ruleManifestId": "python/pytorch-avoid-softmax-with-nllloss-rule@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "pytorch-miss-call-to-zero-grad",
        "version": "1.0",
        "name": "Pytorch miss call to zero grad",
        "shortDescription": "Zero out the gradients before doing a backward pass",
        "longDescription": "Zero out the gradients before doing a backward pass or it would cause gradients to be accumulated instead of being replaced between mini-batches.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "correctness"
        ],
        "ruleManifestId": "python/pytorch-miss-call-to-zero-grad@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "iterating-sequence-modification",
        "version": "1.0",
        "name": "Error prone sequence modification",
        "shortDescription": "Sequence modification while iterating over it might cause unexpected bugs.",
        "longDescription": "The iterable object for the loop expression is calculated once and remains unchanged despite any index changes caused by the sequence modification. This might lead to unexpected bugs. If you need to modify the sequence, we recommend that you first make a copy, such as by using slice notation.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "availability",
            "data-integrity"
        ],
        "ruleManifestId": "python/iterating-sequence-modification@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "missing-encryption-of-sensitive-data-cdk",
        "version": "1.0",
        "name": "AWS missing encryption of sensitive data cdk",
        "shortDescription": "Sensitive or critical information is not encrypted before storage or transmission in the product.",
        "longDescription": "Failing to implement robust data encryption undermines the security guarantees of confidentiality, integrity, and accountability provided by effective encryption practices.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "amazon-s3",
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/missing-encryption-of-sensitive-data-cdk@v1.0",
        "cwes": [
            311
        ],
        "category": "security"
    },
    {
        "ruleId": "bad-exception-handling-practices",
        "version": "1.0",
        "name": "Bad exception handling",
        "shortDescription": "Throwing a base or generic exception might cause important error information to be lost. This can make your code difficult to maintain.",
        "longDescription": "Throwing a base or generic exception might cause important error information to be lost. This can make your code difficult to maintain. We recommend using built-in exceptions or creating a custom exception class that is derived from `Exception` or one of its subclasses.",
        "severity": "Info",
        "language": "Python",
        "tags": [],
        "ruleManifestId": "python/bad-exception-handling-practices@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "use-of-default-credentials-cdk",
        "version": "1.0",
        "name": "Use of Default Credentials CDK",
        "shortDescription": "The product relies on default credentials(including passwords and cryptographic keys) for potentially vital functions.",
        "longDescription": "Using default keys and passwords in product design simplifies manufacturing and deployement but can lead to security risks when administrators don't change them, making it easier for attackers to breach multiple organizations.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/use-of-default-credentials-cdk@v1.0",
        "cwes": [
            1392
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "notebook-variable-redefinition",
        "version": "1.0",
        "name": "Notebook variable redefinition",
        "shortDescription": "A variable is re-defined in multiple cells with different types.",
        "longDescription": "A variable is re-defined in multiple cells with different types. This can cause unexpected behaviours if the order of execution is changed.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning"
        ],
        "ruleManifestId": "python/notebook-variable-redefinition@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "do-not-pass-generic-exception-rule",
        "version": "1.0",
        "name": "Do not pass generic exception rule",
        "shortDescription": "Do not pass generic exception.",
        "longDescription": "Do not pass generic exception.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "consistency",
            "maintainability"
        ],
        "ruleManifestId": "python/do-not-pass-generic-exception-rule@v1.0",
        "cwes": [
            396,
            397
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "not-recommended-apis-high",
        "version": "1.0",
        "name": "Usage of an API that is not recommended - High Severity",
        "shortDescription": "APIs that are not recommended were found - High Severity.",
        "longDescription": "APIs that are not recommended were found. This could indicate a deeper problem in the code. High Severity",
        "severity": "High",
        "language": "Python",
        "tags": [
            "security-context"
        ],
        "ruleManifestId": "python/not-recommended-apis-high@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "insecure-cryptography",
        "version": "1.0",
        "name": "Insecure cryptography",
        "shortDescription": "Weak, broken, or misconfigured cryptography can lead to security vulnerabilities.",
        "longDescription": "Misuse of cryptography-related APIs can create security vulnerabilities. This includes algorithms with known weaknesses, certain padding modes, lack of integrity checks, insufficiently large key sizes, and insecure combinations of the aforementioned.",
        "severity": "Critical",
        "language": "Python",
        "tags": [
            "cryptography",
            "owasp-top10"
        ],
        "ruleManifestId": "python/insecure-cryptography@v1.0",
        "cwes": [
            327
        ],
        "category": "security"
    },
    {
        "ruleId": "s3-partial-encrypt-cdk",
        "version": "1.0",
        "name": "S3 partial encrypt CDK",
        "shortDescription": "An unencrypted bucket could lead to sensitive data exposure.",
        "longDescription": "Failing to encrypt a bucket could lead to sensitive data being exposed to unauthorized users, consider adding `S3_MANAGED` of `KMS_MANAGED` encryption while creating a bucket.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "amazon-s3",
            "aws-cdk"
        ],
        "ruleManifestId": "python/s3-partial-encrypt-cdk@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "cross-site-scripting",
        "version": "1.0",
        "name": "Cross-site scripting",
        "shortDescription": "Relying on potentially untrusted user inputs when constructing web application outputs can lead to cross-site scripting vulnerabilities.",
        "longDescription": "User-controllable input must be sanitized before it's included in output used to dynamically generate a web page. Unsanitized user input can introduce cross-side scripting (XSS) vulnerabilities that can lead to inadvertedly running malicious code in a trusted context.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/cross-site-scripting@v1.0",
        "cwes": [
            20,
            79,
            80
        ],
        "category": "security"
    },
    {
        "ruleId": "default-argument-mutable-objects",
        "version": "1.0",
        "name": "Mutable objects as default arguments of functions",
        "shortDescription": "Default values in Python are created exactly once, when the function is defined. If that object is changed, subsequent calls to the function will refer to the changed object, leading to confusion. ",
        "longDescription": "Default values in Python are created exactly once, when the function is defined. If that object is changed, subsequent calls to the function will refer to the changed object, leading to confusion. We recommend that you set the default value to `None`, then check inside the function if the parameter is `None` before creating the desired mutable object.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "maintainability"
        ],
        "ruleManifestId": "python/default-argument-mutable-objects@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "improper-access-control-cdk",
        "version": "1.0",
        "name": "Improper Access Control CDK",
        "shortDescription": "The software does not restrict or incorrectly restrict access to a resource from an unauthorized actor.",
        "longDescription": "Writing unsanitized user data into logs can allow malicious contents into it. Use appropriate sanitizers or validators on the user data before writing the data into logs.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/improper-access-control-cdk@v1.0",
        "cwes": [
            284
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "pep8-recommendations",
        "version": "1.0",
        "name": "Violation of PEP8 programming recommendations",
        "shortDescription": "Violating PEP8 programming recommendations might make code difficult to read and can introduce ambiguity.",
        "longDescription": "Following PEP8 makes your code clear and more readable. Often there are several ways to perform a similar action in Python. PEP 8 provides recommendations to remove that ambiguity and preserve consistency.",
        "severity": "Info",
        "language": "Python",
        "tags": [
            "consistency",
            "maintainability"
        ],
        "ruleManifestId": "python/pep8-recommendations@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "insecure-temp-file",
        "version": "1.0",
        "name": "Insecure temporary file or directory",
        "shortDescription": "Insecure ways of creating temporary files and directories can lead to race conditions, privilege escalation, and other security vulnerabilities.",
        "longDescription": "Insecure ways of creating temporary files and directories can lead to race conditions (which can be exploited for denial of service attacks) and other security vulnerabilities such as privilege escalation.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "availability",
            "race-condition",
            "owasp-top10"
        ],
        "ruleManifestId": "python/insecure-temp-file@v1.0",
        "cwes": [
            377
        ],
        "category": "security"
    },
    {
        "ruleId": "code-readability",
        "version": "1.0",
        "name": "Complex code hard to maintain",
        "shortDescription": "Complex code can be difficult to read and hard to maintain.",
        "longDescription": "Complex code can be difficult to read and hard to maintain. For example, using three parameters in a single statement while slicing data, and comprehension with more than two subexpressions, can both be hard to understand.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "maintainability"
        ],
        "ruleManifestId": "python/code-readability@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "aws-kmskey-encryption-cdk",
        "version": "1.0",
        "name": "aws kmskey encryption cdk",
        "shortDescription": "Using an AWS KMS key helps follow the standard security advice of granting least privilege to objects generated by the project.",
        "longDescription": "Using AWS KMS keys enables the organization to align with the standard security advice of granting least privilege. The data stored in the S3 bucket remains protected through encryption, and access to both the data and the encryption keys is restricted to authorized entities, reducing the potential security risks associated with data exposure and unauthorized access.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "amazon-s3",
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/aws-kmskey-encryption-cdk@v1.0",
        "cwes": [
            311
        ],
        "category": "security"
    },
    {
        "ruleId": "not-recommended-apis",
        "version": "1.0",
        "name": "Usage of an API that is not recommended",
        "shortDescription": "APIs that are not recommended were found.",
        "longDescription": "APIs that are not recommended were found. This could indicate a deeper problem in the code.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "security-context"
        ],
        "ruleManifestId": "python/not-recommended-apis@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "detect-activated-debug-feature",
        "version": "1.0",
        "name": "Enabling and overriding debug feature",
        "shortDescription": "The Debug feature should not be enabled or overridden.",
        "longDescription": "Don't enable or override an application's debug feature. Instead, use OS environment variables to set up the debug feature.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "efficiency",
            "maintainability"
        ],
        "ruleManifestId": "python/detect-activated-debug-feature@v1.0",
        "cwes": [
            489
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "untrusted-deserialization",
        "version": "1.0",
        "name": "Deserialization of untrusted object",
        "shortDescription": "Deserialization of untrusted objects can lead to security vulnerabilities such as inadvertently running remote code.",
        "longDescription": "Deserialization of untrusted or potentially malformed data can be exploited for denial of service or to induce running untrusted code.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "deserialization",
            "injection",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/untrusted-deserialization@v1.0",
        "cwes": [
            502
        ],
        "category": "security"
    },
    {
        "ruleId": "use-of-inefficient-api",
        "version": "1.0",
        "name": "Use of an inefficient or incorrect API",
        "shortDescription": "Incorrect use of API leads to ambiguity and inconsistency",
        "longDescription": "If there are multiple APIs available to perform similar action, choose the most specialised and efficient one. This helps make your code more readable and easier to understand.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "efficiency",
            "maintainability"
        ],
        "ruleManifestId": "python/use-of-inefficient-api@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "tensorflow-avoid-using-nondeterministic-api",
        "version": "1.0",
        "name": "Avoid using nondeterministic Tensorflow API",
        "shortDescription": "Detects if nondeterministic tensorflow APIs are used.",
        "longDescription": "Detects if tensorflow APIs such as `tf.compat.v1.Session` or `tf.distribute.experimental.ParameterServerStrategy` are used as they can introduce non-determinism.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "maintainability"
        ],
        "ruleManifestId": "python/tensorflow-avoid-using-nondeterministic-api@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "string-concatenation",
        "version": "1.0",
        "name": "Inefficient string concatenation inside loop",
        "shortDescription": "Inefficient string concatenation inside loops results in new object creation which adds quadratic runtime cost.",
        "longDescription": "Concatenating immutable sequences results in a new object. This causes a quadratic runtime cost when done inside loop.",
        "severity": "Info",
        "language": "Python",
        "tags": [
            "efficiency"
        ],
        "ruleManifestId": "python/string-concatenation@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "improper-wildcard-sanitization",
        "version": "1.0",
        "name": "Improper sanitization of wildcards or matching symbols",
        "shortDescription": "Unsanitized wildcards or special matching symbols in user-provided strings can enable attacks and lead to unwanted behavior.",
        "longDescription": "Unsanitized wildcards or special matching symbols in user-provided strings can enable attacks and lead to unwanted behavior, including unwanted filesystem access and denial of service.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection"
        ],
        "ruleManifestId": "python/improper-wildcard-sanitization@v1.0",
        "cwes": [
            155
        ],
        "category": "security"
    },
    {
        "ruleId": "insecure-hashing",
        "version": "1.0",
        "name": "Insecure hashing",
        "shortDescription": "Obsolete, broken, or weak hashing algorithms can lead to security vulnerabilities.",
        "longDescription": "A hashing algorithm is weak if it is easy to determine the original input from the hash or to find another input that yields the same hash. Weak hashing algorithms can lead to security vulnerabilities.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "cryptography",
            "owasp-top10"
        ],
        "ruleManifestId": "python/insecure-hashing@v1.0",
        "cwes": [
            327,
            328
        ],
        "category": "security"
    },
    {
        "ruleId": "do-not-auto-add-or-warning-missing-hostkey-policy",
        "version": "1.0",
        "name": "Using AutoAddPolicy or WarningPolicy",
        "shortDescription": "Using `AutoAddPolicy` or `WarningPolicy` can allow a malicious server to impersonate a trusted server.",
        "longDescription": "We detected a Paramiko host key policy that implicitly trusts server's host key. Do not use `AutoAddPolicy` or `WarningPolicy` as a missing host key policy when creating `SSHClient`. Unverified host keys can allow a malicious server to take control of a trusted server by using the sensitive data (such as authentication information). Instead, use `RejectPolicy` or a custom subclass.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "owasp-top10"
        ],
        "ruleManifestId": "python/do-not-auto-add-or-warning-missing-hostkey-policy@v1.0",
        "cwes": [
            322
        ],
        "category": "security"
    },
    {
        "ruleId": "log-injection",
        "version": "1.0",
        "name": "Log injection",
        "shortDescription": "Using untrusted inputs in a log statement can enable attackers to break the log's format, forge log entries, and bypass log monitors.",
        "longDescription": "User-provided inputs must be sanitized before they are logged. An attacker can use unsanitized input to break a log's integrity, forge log entries, or bypass log monitors.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "data-integrity",
            "injection",
            "owasp-top10"
        ],
        "ruleManifestId": "python/log-injection@v1.0",
        "cwes": [
            117,
            93
        ],
        "category": "security"
    },
    {
        "ruleId": "weak-obfuscation-of-request",
        "version": "1.0",
        "name": "Weak obfuscation of web request",
        "shortDescription": "Weak obfuscation while configuring a web request.",
        "longDescription": "Weak obfuscation while configuring a web request is vulnerable to unauthorized access. Using stronger obfuscation significantly reduces the chances of attacks due to unauthorized access.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/weak-obfuscation-of-request@v1.0",
        "cwes": [
            522,
            202
        ],
        "category": "security"
    },
    {
        "ruleId": "socket-close-platform-compatibility",
        "version": "1.0",
        "name": "Socket close platform compatibility",
        "shortDescription": "The `os.close()` does not work on some platforms.",
        "longDescription": "On some platforms `os.close` does not work for socket file descriptors. This is most noticeable with Windows.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "availability",
            "networking",
            "resource-leak"
        ],
        "ruleManifestId": "python/socket-close-platform-compatibility@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "code-injection",
        "version": "1.0",
        "name": "Unsanitized input is run as code",
        "shortDescription": "Scripts generated from unsanitized inputs can lead to malicious behavior and inadvertently running code remotely.",
        "longDescription": "Running scripts generated from unsanitized inputs (for example, evaluating expressions that include user-provided strings) can lead to malicious behavior and inadvertently running code remotely.",
        "severity": "Critical",
        "language": "Python",
        "tags": [
            "injection",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/code-injection@v1.0",
        "cwes": [
            94
        ],
        "category": "security"
    },
    {
        "ruleId": "aws-unchecked-batch-failures",
        "version": "1.0",
        "name": "Batch request with unchecked failures",
        "shortDescription": "Not checking which items have failed can lead to loss of data.",
        "longDescription": "A batch request might return one or more failed items. To prevent data loss, make sure your code checks for failed items.",
        "severity": "Info",
        "language": "Python",
        "tags": [
            "aws-python-sdk",
            "batch-operations",
            "data-integrity"
        ],
        "ruleManifestId": "python/aws-unchecked-batch-failures@v1.0",
        "cwes": [
            253
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "aws-polling-instead-of-waiter",
        "version": "1.0",
        "name": "Inefficient polling of AWS resource",
        "shortDescription": "Custom polling can be inefficient and prone to error. Consider using AWS waiters instead.",
        "longDescription": "Custom polling can be inefficient and prone to error. Consider using AWS waiters instead. A waiter is an abstraction used to poll AWS resources, such as DynamoDB tables or Amazon S3 buckets, until a desired state is reached.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "aws-python-sdk",
            "efficiency"
        ],
        "ruleManifestId": "python/aws-polling-instead-of-waiter@v1.0",
        "cwes": [
            19
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "hardcoded-bind-all-interfaces",
        "version": "1.0",
        "name": "Hardcoded interface binding",
        "shortDescription": "Binding to all network interfaces can open a service up  to traffic on interfaces that are not properly documented or secured.",
        "longDescription": "Binding to all network interfaces can open a service up to  traffic on interfaces that are not properly documented or secured. To ensure  that connections from anywhere are not accepted, don't bind to '0.0.0.0'  using a hardcoded reference.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "availability",
            "networking"
        ],
        "ruleManifestId": "python/hardcoded-bind-all-interfaces@v1.0",
        "cwes": [
            605
        ],
        "category": "security"
    },
    {
        "ruleId": "hardcoded-ip-address",
        "version": "1.0",
        "name": "Hardcoded IP address",
        "shortDescription": "Hardcoding an IP address can cause security problems.",
        "longDescription": "We recommend that you do not hardcode IP addresses because they might change. A hardcoded IP address can make your code vulnerable to denial of service attacks and IP address spoofing to bypass security checks.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "networking",
            "security-context"
        ],
        "ruleManifestId": "python/hardcoded-ip-address@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "hardcoded-credentials",
        "version": "1.0",
        "name": "Hardcoded credentials",
        "shortDescription": "Credentials, such as passwords and access keys, should not be hardcoded in source code.",
        "longDescription": "Access credentials, such as passwords and access keys, should not be hardcoded in source code. Hardcoding credentials may cause leaks even after removing them. This is because version control systems might retain older versions of the code. Credentials should be stored securely and obtained from the runtime environment.",
        "severity": "Critical",
        "language": "Python",
        "tags": [
            "secrets",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/hardcoded-credentials@v1.0",
        "cwes": [
            798
        ],
        "category": "security"
    },
    {
        "ruleId": "server-side-request-forgery",
        "version": "1.0",
        "name": "Server-side request forgery",
        "shortDescription": "Insufficient sanitization of potentially untrusted URLs on the server side can allow server requests to unwanted destinations.",
        "longDescription": "Insufficient sanitization of potentially untrusted URLs on the server side can lead to the server issuing requests to unwanted hosts, ports, or protocols, which can bypass proxies, firewalls, and other security measures.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "configuration",
            "injection",
            "networking",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/server-side-request-forgery@v1.0",
        "cwes": [
            918
        ],
        "category": "security"
    },
    {
        "ruleId": "module-injection",
        "version": "1.0",
        "name": "Module injection",
        "shortDescription": "Untrusted user imports in the `importlib.import_module()` function allow attacks.",
        "longDescription": "Untrusted user imports in Python allow an attacker to load arbitrary code. To prevent malicious code from running, only allow imports from trusted libraries or from libraries on allow lists.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection",
            "owasp-top10"
        ],
        "ruleManifestId": "python/module-injection@v1.0",
        "cwes": [
            706
        ],
        "category": "security"
    },
    {
        "ruleId": "unnecessary-iteration",
        "version": "1.0",
        "name": "Unnecessary iteration",
        "shortDescription": "Iteration when only one item is needed from a list is inefficient.",
        "longDescription": "Iteration when only one item is needed from list is inefficient and can make your code difficult to read.",
        "severity": "Info",
        "language": "Python",
        "tags": [
            "efficiency"
        ],
        "ruleManifestId": "python/unnecessary-iteration@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "tensorflow-control-sources-of-randomness",
        "version": "1.0",
        "name": "Tensorflow control sources of randomness",
        "shortDescription": "Detects if a random seed is set before random number generation.",
        "longDescription": "Detects if a random seed is set before random number generation. Setting a seed is important for improving reproducibility and avoiding non-determinism.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "maintainability"
        ],
        "ruleManifestId": "python/tensorflow-control-sources-of-randomness@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "missing-authentication-for-critical-function-cdk",
        "version": "1.0",
        "name": "Missing Authentication for Critical Function CDK",
        "shortDescription": "Missing authentication checks can lead to unauthorized access to a resource or performance of an action.",
        "longDescription": "When authentication checks are not applied, users are able to access data or perform actions that they should not be allowed to access or perform. The lack of authentication checks can cause the exposure of information, denial of service, and arbitrary code execution. We recommend that you apply authentication checks to all access points.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "amazon-s3",
            "aws-cdk",
            "efficiency"
        ],
        "ruleManifestId": "python/missing-authentication-for-critical-function-cdk@v1.0",
        "cwes": [
            306
        ],
        "category": "code-quality"
    },
    {
        "ruleId": "not-recommended-apis-medium",
        "version": "1.0",
        "name": "Usage of an API that is not recommended - Medium Severity",
        "shortDescription": "APIs that are not recommended were found - Medium Severity.",
        "longDescription": "APIs that are not recommended were found. This could indicate a deeper problem in the code - Medium Severity.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "security-context"
        ],
        "ruleManifestId": "python/not-recommended-apis-medium@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "unsafe-cloudpickle-load",
        "version": "1.0",
        "name": "Unsafe Cloudpickle Load",
        "shortDescription": "Pickling issues on Cloudpickle Load.",
        "longDescription": "Detects the usage of cloudpickle.load for deserializing data from a file, which can lead to insecure deserialization vulnerabilities.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "deserialization",
            "owasp-top10",
            "top25-cwes"
        ],
        "ruleManifestId": "python/unsafe-cloudpickle-load@v1.0",
        "cwes": [
            502
        ],
        "category": "security"
    },
    {
        "ruleId": "sns-no-bind-subscribe-publish-rule",
        "version": "1.0",
        "name": "Incorrect binding of SNS publish operations",
        "shortDescription": "Incorrect binding of SNS publish operations with the `subscribe` or `create_topic` operations might lead to latency issues.",
        "longDescription": "Binding of SNS publish operations with `subscribe` or `create_topic` operations can cause latency issues with newly created topics.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "amazon-sns",
            "availability",
            "aws-python-sdk"
        ],
        "ruleManifestId": "python/sns-no-bind-subscribe-publish-rule@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "pytorch-create-tensors-directly-on-device",
        "version": "1.0",
        "name": "PyTorch create tensors directly on device",
        "shortDescription": "Creating PyTorch tensors on the CPU and then moving them to the device is inefficient.",
        "longDescription": "Creating PyTorch tensors on the CPU and then moving them to the device impacts the performance.",
        "severity": "Medium",
        "language": "Python",
        "tags": [
            "machine-learning",
            "efficiency"
        ],
        "ruleManifestId": "python/pytorch-create-tensors-directly-on-device@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "hashlib-constructor",
        "version": "1.0",
        "name": "Inefficient new method from hashlib",
        "shortDescription": "The constructors for the `hashlib` module are faster than `new()`",
        "longDescription": "The constructors for the `hashlib` module are faster than `new()`. We recommend using `hashlib` constructors instead.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "efficiency"
        ],
        "ruleManifestId": "python/hashlib-constructor@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "dangerous-global-variables",
        "version": "1.0",
        "name": "Dangerous global variables",
        "shortDescription": "Global variables can be dangerous and cause bugs because they can be simultaneously accessed from multiple sections of a program.",
        "longDescription": "Global variables can be dangerous and cause bugs because they can be simultaneously accessed from multiple sections of a program. Most global variable bugs are caused when one function reading and acting on the value of a global variable before another function has the chance to set it to an appropriate value. We recommend using a configuration module to mutate global state.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "maintainability"
        ],
        "ruleManifestId": "python/dangerous-global-variables@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "multiple-values-in-return",
        "version": "1.0",
        "name": "Multiple values in return statement is prone to error",
        "shortDescription": "Methods that return multiple values can be difficult to read and prone to error.",
        "longDescription": "Methods that return multiple values can be difficult to read and prone to error. Return a small class or `namedtuple` instance instead.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "maintainability"
        ],
        "ruleManifestId": "python/multiple-values-in-return@v1.0",
        "cwes": null,
        "category": "code-quality"
    },
    {
        "ruleId": "ldap-injection",
        "version": "1.0",
        "name": "LDAP injection",
        "shortDescription": "LDAP queries that rely on potentially untrusted inputs can allow attackers to read or modify sensitive data, run code, and perform other unwanted actions.",
        "longDescription": "An LDAP query that relies on potentially untrusted inputs might allow attackers to inject unwanted elements into the query. This can allow attackers to read or modify sensitive data, run code, and perform other unwanted actions.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "injection",
            "ldap",
            "owasp-top10"
        ],
        "ruleManifestId": "python/ldap-injection@v1.0",
        "cwes": [
            90
        ],
        "category": "security"
    },
    {
        "ruleId": "clear-text-credentials",
        "version": "1.0",
        "name": "Clear text credentials",
        "shortDescription": "Credentials that are stored in clear text can be intercepted by a malicious actor.",
        "longDescription": "Credentials that are stored in clear text in memory or written to log files can be intercepted by a malicious actor.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "access-control",
            "information-leak",
            "secrets",
            "owasp-top10"
        ],
        "ruleManifestId": "python/clear-text-credentials@v1.0",
        "cwes": [
            916,
            328
        ],
        "category": "security"
    },
    {
        "ruleId": "s3-verify-bucket-owner",
        "version": "1.0",
        "name": "Missing S3 bucket owner condition",
        "shortDescription": "Not setting the S3 bucket owner condition might introduce a risk of accidentally using a wrong bucket.",
        "longDescription": "Not setting the S3 bucket owner condition might introduce a risk of accidentally using a wrong bucket. For example, a configuration error could lead to accidentally writing production data into test accounts.",
        "severity": "Low",
        "language": "Python",
        "tags": [
            "amazon-s3",
            "aws-python-sdk",
            "data-integrity",
            "security-context"
        ],
        "ruleManifestId": "python/s3-verify-bucket-owner@v1.0",
        "cwes": null,
        "category": "security"
    },
    {
        "ruleId": "aws-missing-encryption-cdk",
        "version": "1.0",
        "name": "AWS missing encryption CDK",
        "shortDescription": "The AWS resource is missing appropriate encryption.",
        "longDescription": "Encryption ensure that the data is safe and is not sensitive to leakage. Ensure appropriate encryption strategies are used to prevent exposure of such sensitive data.",
        "severity": "High",
        "language": "Python",
        "tags": [
            "aws-cdk"
        ],
        "ruleManifestId": "python/aws-missing-encryption-cdk@v1.0",
        "cwes": [
            311
        ],
        "category": "security"
    }
]
"""

def parse_detectors():
    """
    Parse the CodeGuru detectors JSON file and extract relevant information - vulnerability names and descriptions.
    """
    detectors = json.loads(JSON_STRING)

    parsed = []
    for detector in detectors:

        if detector["severity"] in ["Low", "Info"]:
            continue

        parsed.append({
            "name" : detector["name"],
            "description" : detector["longDescription"],
        })

    return parsed

CODEGURU_DETECTORS = parse_detectors()

# print(CODEGURU_DETECTORS)
# print(len(CODEGURU_DETECTORS))
"""Language-neutral pattern tables (used only to classify evidence inside parsed nodes)."""

from __future__ import annotations

import re

# ---- identity / privilege vocabulary ---------------------------------------------------------
IDENT_FIELD = re.compile(
    r"^(user[-_ ]?id|owner[-_ ]?id|uid|account[-_ ]?id|customer[-_ ]?id|author[-_ ]?id|member[-_ ]?id|"
    r"logged[-_ ]?in[-_ ]?user[-_ ]?id|current[-_ ]?user[-_ ]?id|x[-_]user[-_]?id|x[-_]user|userid|"
    r"role|roles|user[-_ ]?role|x[-_]role|is[-_ ]?admin|admin|permissions?|user)$", re.I)
ROLE_FIELD = re.compile(r"^(role|roles|user[-_ ]?role|x[-_]role|is[-_ ]?admin|admin|permissions?)$", re.I)
OWNER_KEY = re.compile(r"(^|_)(owner|user|author|created_?by|account|customer|tenant|org|organization|member|company)(_?id)?$|"
                       r"^(owner|userId|user_id|ownerId|authorId|createdBy|tenantId|accountId)$", re.I)
PRIV_KEYS = re.compile(r"^(role|roles|is_?admin|admin|is_?superuser|is_?staff|permissions?|user_?type|account_?type|"
                       r"access_?level|privilege|is_?root)$", re.I)
PRIV_LITERALS = {"admin", "administrator", "superuser", "super_admin", "superadmin", "root", "sysadmin", "super-admin"}
SENSITIVE_FIELD = re.compile(r"(pass(word|wd)?|pwd|hash|salt|secret|token|api_?key|private_?key|card|cvv|ssn|otp|mfa|"
                             r"refresh)", re.I)
SENSITIVE_FIELD_EXCLUDE = re.compile(r"(passes|bypass|compass|tokenizer|tokens_used|token_count|hashtag|cardinal|discard)", re.I)
REGISTRATION_PATH = re.compile(r"(register|signup|sign[-_]up|sign_up|join|onboard|create[-_]?(user|account)|"
                               r"/users?/?$|/accounts?/?$|/members?/?$)", re.I)
SENSITIVE_PATH = re.compile(r"(^|/)(admin|debug|actuator|internal|console|config|env|metrics|backup|export|dump|manage|"
                            r"secret|private|users?|accounts?|payments?|orders?|invoices?|billing|checkout|wallet|"
                            r"profile|settings|upload|delete|roles?|permissions?|tokens?|keys?)(/|$|\.)", re.I)
ADMINLIKE_PATH = re.compile(r"(^|/)(admin|administrator|superuser|manage|management|internal|backoffice|console|"
                            r"roles?|permissions?|impersonate|grant|promote)(/|$)", re.I)
DEFAULT_PUBLIC = [r"login", r"log-?in", r"signin", r"sign-?in", r"logout", r"sign-?up", r"signup", r"register",
                  r"forgot", r"reset-?password", r"password-?reset", r"verify", r"health", r"healthz", r"ping",
                  r"status", r"ready", r"live", r"version", r"robots", r"favicon", r"webhook", r"oauth", r"callback",
                  r"auth/", r"\.well-known", r"public", r"^/$", r"swagger", r"openapi", r"docs$"]

# ---- guard classification by *name* (certainty "name") --------------------------------------
GUARD_NAME = {
    "authentication": re.compile(r"(authenticat|isauth|requireauth|ensureauth|isloggedin|loggedin|verifytoken|checkauth|"
                                 r"^protect$|requirelogin|login_?required|jwt|passport|expressjwt|withauth|requireuser|"
                                 r"^auth(middleware|guard|check)?$|authguard|isauthenticated|jwt_?required|"
                                 r"verify_?jwt|token_?required|bearer|apikey|api_?key_?required|get_current_user|"
                                 r"current_user|oauth2|httpbearer|useauth)", re.I),
    "authorization": re.compile(r"(isadmin|requireadmin|adminonly|admin_?required|requirerole|checkrole|^authorize|"
                                r"restrictto|hasrole|haspermission|permit|checkpermission|rolesguard|roles?_?required|"
                                r"permission_?required|staff_?member_?required|user_?passes_?test|superuser_?required|"
                                r"requirepermission|ability|^can$|policy|acl|rbac|require_?scope|scopes?)", re.I),
    "ownership": re.compile(r"(isowner|checkownership|owneroradmin|belongsto|canaccess|canedit|ownershipguard)", re.I),
    "csrf": re.compile(r"(csrf|csurf|xsrf|lusca)", re.I),
    "rate_limit": re.compile(r"(rate_?limit|limiter|throttl|slowdown)", re.I),
    "validation": re.compile(r"(validat|celebrate|joi|zod|ajv|sanitiz|check\(|schema)", re.I),
}
NOT_A_GUARD = re.compile(r"^(cors|helmet|morgan|compression|bodyparser|json|urlencoded|static|cookieparser|logger|"
                         r"errorhandler|session|multer|upload|favicon|serveindex)$", re.I)

# ---- verified identity expressions ----------------------------------------------------------
IDENTITY_EXPR = re.compile(
    r"^(await\s+)?(?:"
    r"(?:req|request)\.(?:user|auth|userId|currentUser|account|identity|principal|session\.(?:user\w*|userId|passport)|"
    r"jwt|token\.sub|claims)\b|"
    r"(?:res|response)\.locals\.(?:user|userId|auth|currentUser)\b|ctx\.state\.(?:user|auth|userId)\b|"
    r"ctx\.user\b|current_user\b|g\.(?:user|current_user)\b|request\.user\b|session\[['\"]\w*user\w*['\"]\]|"
    r"session\.get\(['\"]\w*user\w*['\"]\)|get_jwt_identity\(\)|get_jwt\(\)|get_current_user\b|current_user\b|"
    r"principal\b|authentication\.(?:name|principal)\b|SecurityContextHolder\b|User\.Identity\b|"
    r"auth\(\)\.userId|getServerSession\b|getSession\b)")

# ---- request sources --------------------------------------------------------------------------
REQUEST_SOURCE = re.compile(
    r"^(?:await\s+)?(?:req|request|ctx\.request|ctx|event)\.(body|params|query|headers|cookies|signedCookies|files|file|"
    r"args|form|values|json|data|GET|POST|FILES|COOKIES|META|path_params|query_params)"
    r"(?:\.(\w+)|\[['\"]([\w\-]+)['\"]\]|\.get\(['\"]([\w\-]+)['\"])?")

# ---- sinks (callee text) -----------------------------------------------------------------------
FS_JS = re.compile(r"^(?:fs|fsp|fse|fs\.promises|promises|fsExtra|fs-extra)\.(readFile|readFileSync|createReadStream|"
                   r"writeFile|writeFileSync|createWriteStream|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|"
                   r"rmdir|rmdirSync|readdir|readdirSync|rename|renameSync|copyFile|copyFileSync|stat|statSync|"
                   r"access|existsSync|open|openSync|mkdir|mkdirSync|readlink|remove|copy|move|outputFile|ensureDir)$")
FS_SEND = re.compile(r"^(?:res|reply|response|ctx)\.(sendFile|sendfile|download|attachment)$")
FS_PY = re.compile(r"^(open|io\.open|codecs\.open|send_file|send_from_directory|os\.remove|os\.unlink|os\.rmdir|"
                   r"os\.listdir|os\.rename|os\.replace|os\.makedirs|os\.mkdir|os\.stat|os\.walk|shutil\.\w+|"
                   r"FileResponse|FileSystemStorage\.\w+|default_storage\.\w+|pathlib\.Path\.\w+)$")
FS_PY_METHOD = re.compile(r"\.(read_text|read_bytes|write_text|write_bytes|unlink|open|rmdir|iterdir)$")
ARCHIVE = re.compile(r"(?:^|\.)(extractall|extract|unzip|unpack_archive|extractFile)$|^(tar|zip|unzipper|AdmZip|decompress)\.")
SANITIZE_PATH = re.compile(r"(^|\.)(basename|secure_filename|sanitize|sanitizeFilename|sanitize_filename|slugify|"
                           r"get_valid_filename|escape|parse|normalize_filename)$")
CONTAIN_CALL = re.compile(r"(startsWith|startswith|is_relative_to|commonpath|commonprefix|relative|realpath|isSubPath|"
                          r"isInside|safe_join|within|abspath|resolve)\b")
HTTP_JS = re.compile(r"^(?:axios|got|superagent|needle|request|fetch|nodeFetch|undici|ky|http|https|"
                     r"axios\.(?:get|post|put|patch|delete|head|request)|got\.(?:get|post|put|patch|delete|stream)|"
                     r"request\.(?:get|post|put|delete)|superagent\.(?:get|post|put|delete)|needle\.(?:get|post)|"
                     r"(?:http|https)\.(?:get|request)|undici\.(?:request|fetch)|"
                     r"(?:page|browser)\.(?:goto|newPage)|puppeteer\.\w+|wkhtmltopdf|"
                     r"(?:this\.)?(?:httpService|http|httpClient)\.(?:get|post|put|delete|request)|"
                     r"(?:ogs|unfurl|metascraper|linkPreview|getLinkPreview|sharp|jimp|Jimp\.read))$")
HTTP_PY = re.compile(r"^(?:requests\.(?:get|post|put|patch|delete|head|request)|httpx\.(?:get|post|put|patch|delete|head|request)|"
                     r"urllib\.request\.(?:urlopen|urlretrieve)|urlopen|urlretrieve|urllib3\.\w+|"
                     r"(?:\w+\.)?(?:session|client|http|http_client|s)\.(?:get|post|put|patch|delete|head|request)|"
                     r"aiohttp\.\w+|pdfkit\.from_url|imgkit\.from_url|HTML|Image\.open|wget\.download|"
                     r"(?:urllib\.request\.)?Request|webbrowser\.open|ftplib\.FTP|smtplib\.SMTP)$")
URL_KEYS = re.compile(r"^(url|uri|baseURL|baseUrl|host|hostname|href|endpoint|target|link|address|server|proxy)$", re.I)
URL_FIELD = re.compile(r"(url|uri|href|link|webhook|callback|endpoint|image|avatar|feed|target|dest|redirect|host|proxy|site|source)", re.I)
REDIRECT_JS = re.compile(r"^(?:res|reply|response|ctx)\.(redirect|location)$")
REDIRECT_PY = re.compile(r"^(redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse|redirect_to|"
                         r"flask\.redirect|werkzeug\.utils\.redirect|django\.shortcuts\.redirect)$")
RESPONSE_JS = re.compile(r"^(?:res|reply|response)(?:\.\w+\([^)]*\))*\.(json|send|end|render|jsonp|sendStatus|status)$|"
                         r"^(?:res|reply|response)\.(json|send|end|render|jsonp)$")
RESPONSE_PY = re.compile(r"^(jsonify|JsonResponse|Response|render|render_template|HttpResponse|make_response|"
                         r"JSONResponse|ORJSONResponse|json\.dumps|flask\.jsonify|rest_framework\.response\.Response)$")
WRITE_NAMES = re.compile(r"^(save|create|createMany|insertMany|insertOne|insert|update|updateOne|updateMany|"
                         r"findByIdAndUpdate|findOneAndUpdate|findByIdAndDelete|findOneAndDelete|findByIdAndRemove|"
                         r"deleteOne|deleteMany|delete|destroy|remove|upsert|bulkCreate|bulk_create|add|add_all|"
                         r"update_or_create|get_or_create|replaceOne|findOneAndReplace|persist|merge|set|run|"
                         r"commit|execute|bulk_update|save_changes|SaveChanges|SaveChangesAsync|Create|Save|Delete|Updates|Update|"
                         r"deleteById|deleteAll|saveAndFlush|Remove|RemoveAsync|Add|AddAsync)$")
LOOKUP_NAMES = re.compile(r"^(findById|findOne|findByPk|findUnique|findFirst|findOneBy|findOneOrFail|findByIdAndUpdate|"
                          r"findByIdAndDelete|findByIdAndRemove|findOneAndUpdate|findOneAndDelete|deleteOne|updateOne|"
                          r"destroy|delete|update|get|get_or_404|first_or_404|get_object_or_404|getById|getOne|"
                          r"find|findAll|findMany|findAndCountAll|all|filter|filter_by|where|query|"
                          r"findUniqueOrThrow|findFirstOrThrow|get_object|getReference|findOneById|"
                          r"first|First|Find|Take|Where|Preload|fetch|find_one|find_all|retrieve|FindAsync|FirstOrDefault|"
                          r"FirstOrDefaultAsync|SingleOrDefault|SingleOrDefaultAsync|GetById|GetByIdAsync|deleteById|getReferenceById)$")
SINGLE_LOOKUP = re.compile(r"^(findById|findOne|findByPk|findUnique|findFirst|findOneBy|findOneOrFail|findByIdAndUpdate|"
                           r"findByIdAndDelete|findByIdAndRemove|findOneAndUpdate|findOneAndDelete|deleteOne|updateOne|"
                           r"destroy|delete|update|get|get_or_404|first_or_404|get_object_or_404|getById|getOne|"
                           r"findUniqueOrThrow|findFirstOrThrow|findOneById|getReference|find_one|retrieve|first|"
                           r"First|Take|Find|fetch|FindAsync|FirstOrDefault|FirstOrDefaultAsync|SingleOrDefault|"
                           r"SingleOrDefaultAsync|GetById|GetByIdAsync|deleteById|getReferenceById)$")
MODELISH = re.compile(r"^(?:this\.|_)?(?:[A-Z]\w*|\w*[Cc]ontext\w*|\w*(?:Model|Repository|Repo|Service|Collection|collection|repository|repo|"
                      r"db|prisma|knex|manager|em|session|objects|query|store|dao|DAO|Dao)\w*)(?:\.\w+)*$")
NON_DB_RECEIVER = re.compile(r"^(?:res|req|response|request|reply|ctx|Map|Set|Object|Array|JSON|Math|Promise|"
                             r"cache|localStorage|sessionStorage|headers|params|console|logger|log|os|path|fs|"
                             r"process|Date|Number|String|Buffer|crypto|bcrypt|jwt|axios|URL|URLSearchParams|"
                             r"util|_|lodash|self|cls|dict|list|str|json|time|re|random|datetime|secrets)\b")
PROJECTION_KEYS = {"select", "attributes", "projection", "fields", "only", "exclude", "omit", "columns", "values",
                   "values_list", "defer", "with_entities", "load_only"}
PICK_FUNCS = re.compile(r"(^|\.)(pick|omit|permit|allowedFields|only|whitelist|sanitizeBody|pickBy)$")
CAST_FUNCS = {"parseInt", "Number", "parseFloat", "int", "float", "Math.floor", "Math.round", "bool", "Boolean", "len",
              "uuid.UUID", "UUID", "ObjectId", "mongoose.Types.ObjectId", "Types.ObjectId", "Decimal"}
VALIDATION_CALL = re.compile(r"(includes|startsWith|startswith|endsWith|endswith|indexOf|test|match|has|allow|valid|"
                             r"isSafe|isUrl|whitelist|safe_url|is_safe_url|url_has_allowed_host|urlparse|new URL|"
                             r"hostname|netloc|ipaddress|is_private|dns|lookup|resolve|in_)", re.I)
OWNERSHIP_CALL = re.compile(r"(owner|ownership|canAccess|canEdit|canView|canDelete|belongsTo|isOwner|authorize|"
                            r"checkAccess|assertAccess|policy|can\(|ability|has_object_permission|check_object_permissions|"
                            r"get_queryset|accessibleBy|userCan|permitted)", re.I)
CORS_NAME = re.compile(r"^(cors|CORS|CorsMiddleware|CORSMiddleware)$")
TOKEN_SIGN = re.compile(r"^(jwt|jsonwebtoken|jose|pyjwt|JWT)\.(sign|encode)$|^(sign|encode|jwtSign|signAsync)$")
TOKEN_DECODE = re.compile(r"^(jwt|jsonwebtoken|jose|pyjwt|JWT)\.decode$")
TOKEN_VERIFY = re.compile(r"(^|\.)(verify|jwtVerify|verifyAsync|decode_token|verify_jwt_in_request|"
                          r"jwt_required|get_jwt_identity|authenticate|validate_token|checkToken|parse_token)$")
SENSITIVE_FILE_NAMES = re.compile(
    r"(^\.env(\..*)?$|\.(bak|old|orig|swp|sql|sqlite3?|db|dump|pem|key|p12|pfx|npmrc|pypirc|log|tar|tgz|zip|gz|7z|rar)$|"
    r"^\.htpasswd$|~$|^id_(rsa|dsa|ecdsa|ed25519)$|^(backup|dump|database|credentials|secrets?)\b|"
    r"^config\.(php|inc)$|^wp-config|^\.git$)", re.I)
CONVENTIONAL_PUBLIC_DIRS = {"public", "static", "www", "wwwroot", "webroot", "htdocs", "html", "assets", "dist", "build",
                            "uploads", "files", "downloads", "media", "public_html"}


def is_public_path(path: str, extra=()) -> bool:
    lowered = (path or "").lower()
    return any(re.search(p, lowered) for p in list(DEFAULT_PUBLIC) + list(extra))


def classify_guard_name(name: str) -> list:
    """Guard kinds suggested by a name alone (certainty 'name')."""
    short = (name or "").split(".")[-1].split("(")[0]
    if NOT_A_GUARD.match(short):
        return []
    kinds = [k for k, rx in GUARD_NAME.items() if rx.search(short) or rx.search(name or "")]
    if "authorization" in kinds and "authentication" in kinds:
        # "authorize" / "requireAdmin" style names are authorization first
        if re.search(r"admin|role|permission|authorize|scope|acl|policy", short, re.I):
            kinds.remove("authentication")
    return kinds

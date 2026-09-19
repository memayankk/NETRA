from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pathlib import Path
from collections import Counter
from itertools import combinations
from datetime import datetime
import json, re, math, csv, io, tempfile, os, hashlib, hmac, base64, sqlite3, secrets, time
from contextvars import ContextVar
import networkx as nx

BASE = Path(__file__).resolve().parent.parent
DATA_FILE = BASE / "data" / "sample_records.json"
app = FastAPI(title="SIH26189 — AI-Powered Criminal Network Analysis", version="4.0.0")
# Allows the demo UI to call the local API even when index.html is opened directly.
# Restrict allowed origins before any production deployment.
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=BASE / "app" / "static"), name="static")

USER_DB = BASE / "data" / "netra_users.db"
SESSION_SECRET = os.getenv("NETRA_SESSION_SECRET", "NETRA-SIH-26189-DEMO-SESSION-SECRET-2026").encode("utf-8")
ACTOR = ContextVar("netra_actor", default="system")

def _make_session_token(username, role, ttl=8*60*60):
    payload = json.dumps({"u": username, "r": role, "e": int(time.time()) + ttl}, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    sig = hmac.new(SESSION_SECRET, body.encode("ascii"), hashlib.sha256).hexdigest()
    return body + "." + sig

def _read_session_token(token):
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(SESSION_SECRET, body.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected): return None
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8"))
        if int(data.get("e", 0)) < int(time.time()): return None
        if not data.get("u") or not data.get("r"): return None
        return {"username": data["u"], "role": data["r"], "expires": int(data["e"])}
    except Exception:
        return None

def _db():
    conn = sqlite3.connect(USER_DB)
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1)")
    conn.commit()
    return conn

def _hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 180_000)
    return salt.hex() + ":" + digest.hex()

def _verify_password(password, encoded):
    try:
        salt_hex, digest_hex = encoded.split(":", 1)
        test = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 180_000).hex()
        return secrets.compare_digest(test, digest_hex)
    except Exception:
        return False

def _seed_users():
    conn = _db()
    if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        conn.execute("INSERT INTO users(username,password_hash,role,active) VALUES (?,?,?,1)", ("memayankk", _hash_password("Netra@2026"), "Investigator"))
        conn.execute("INSERT INTO users(username,password_hash,role,active) VALUES (?,?,?,1)", ("admin", _hash_password("NetraAdmin@2026"), "Administrator"))
        conn.commit()
    conn.close()
_seed_users()

records = json.loads(DATA_FILE.read_text(encoding="utf-8"))
audit_log = []
report_focus = {}
graph = nx.MultiDiGraph()
DEFAULT_CASE_ID = "CASE-DEMO-001"
cases = {
    DEFAULT_CASE_ID: {
        "id": DEFAULT_CASE_ID,
        "title": "Synthetic Network Investigation",
        "status": "OPEN",
        "description": "Demonstration case built only from synthetic records.",
    }
}

@app.middleware("http")
async def auth_guard(request, call_next):
    path=request.url.path
    if path.startswith("/api/") and not path.startswith("/api/auth/"):
        token=request.cookies.get("netra_session")
        session=_read_session_token(token) if token else None
        if not session:
            return JSONResponse({"detail":"Authentication required"}, status_code=401)
        ctx=ACTOR.set(session["username"])
        try: return await call_next(request)
        finally: ACTOR.reset(ctx)
    return await call_next(request)

PEOPLE = ["Rohan Mehta", "Amit Verma", "Suresh Khan"]
ENTITY_PATTERNS = {
    "PHONE": r"\b[6-9]\d{9}\b",
    "VEHICLE": r"\b[A-Z]{2}\d{2}[A-Z]{1,3}\d{4}\b",
    "ORG": r"\b(?:[A-Z][A-Za-z&.\-]+\s+){0,3}(?:Logistics|Industries|Enterprises|Services|Traders)\b",
    "LOCATION": r"\b(?:Vaishali Nagar|Jaipur Railway Station|Jaipur|Delhi|Mumbai|Kota|Udaipur)\b",
    "ACCOUNT": r"\b(?:AC|ACC)[-_]?\d{6,14}\b",
    "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
}
STOPWORDS={"The","This","That","Incident","Report","FIR","Police","Officer","Subject","Date","Location","Person","Phone","Vehicle","Account","Amount"}
TYPE_META = {
    "PERSON": {"label":"Person", "icon":"👤"}, "PHONE":{"label":"Phone","icon":"📞"},
    "VEHICLE":{"label":"Vehicle","icon":"🚗"}, "LOCATION":{"label":"Location","icon":"📍"},
    "ORG":{"label":"Organization","icon":"🏢"}, "ACCOUNT":{"label":"Account","icon":"🏦"},
    "EMAIL":{"label":"Email","icon":"✉️"},
    "CASE":{"label":"Case","icon":"📁"}, "EVENT":{"label":"Event","icon":"📅"},
}
class Record(BaseModel):
    id: str
    type: str = "REPORT"
    text: str
    case_id: str = DEFAULT_CASE_ID
    event_date: str | None = None
    evidence_hash: str | None = None

class Case(BaseModel):
    id: str
    title: str
    description: str = ""
    status: str = "OPEN"

class AssistantRequest(BaseModel):
    query: str

class ReportFocusRequest(BaseModel):
    case_id: str = DEFAULT_CASE_ID
    entity_ids: list[str] = []

class AIIngestRequest(BaseModel):
    text: str
    record_type: str = "AI-REPORT"
    case_id: str = DEFAULT_CASE_ID
    record_id: str | None = None


def calculate_evidence_hash(record):
    canonical = json.dumps({
        "id": record.get("id"),
        "type": record.get("type"),
        "text": record.get("text", ""),
        "case_id": record.get("case_id", DEFAULT_CASE_ID),
        "event_date": record.get("event_date"),
    }, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def ensure_evidence_hashes():
    for r in records:
        if not r.get("evidence_hash"):
            r["evidence_hash"] = calculate_evidence_hash(r)

def norm_id(typ, label): return f"{typ}:{re.sub(r'[^a-z0-9]+','_',label.lower()).strip('_')}"

def extract_entities(text):
    found=[]
    for p in PEOPLE:
        if re.search(re.escape(p), text, re.I):
            found.append({"id":norm_id("PERSON",p),"label":p,"type":"PERSON"})
    # Lightweight person-name extraction for demo FIR/report text.
    for m in re.finditer(r"\b(?:Mr\.?|Ms\.?|Mrs\.?|Dr\.?)\s+([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,}){1,2})\b", text):
        label=m.group(1).strip()
        if label not in STOPWORDS:
            found.append({"id":norm_id("PERSON",label),"label":label,"type":"PERSON"})
    for typ, pattern in ENTITY_PATTERNS.items():
        flags = 0 if typ == "ORG" else re.I
        for value in re.findall(pattern, text, flags):
            label=value.strip(" ,.;:\n\t")
            if typ == "ORG":
                # Keep only the organization phrase ending in a known business suffix.
                words=label.split()
                for i in range(max(0,len(words)-4),len(words)):
                    if words[i].endswith(("Logistics","Industries","Enterprises","Services","Traders")):
                        label=" ".join(words[i-3:i+1]) if i>=3 else " ".join(words[:i+1])
                if len(label.split())>4: continue
            found.append({"id":norm_id(typ,label),"label":label,"type":typ})
    return list({x["id"]:x for x in found}.values())

def decode_upload(filename, raw):
    ext=Path(filename).suffix.lower()
    if ext == ".pdf":
        try:
            from pypdf import PdfReader
            reader=PdfReader(io.BytesIO(raw))
            return "\n".join(page.extract_text() or "" for page in reader.pages).strip()
        except Exception as exc:
            raise HTTPException(400, f"PDF extraction failed: {exc}")
    if ext == ".json":
        try:
            obj=json.loads(raw.decode("utf-8",errors="replace"))
            if isinstance(obj, list):
                return "\n".join(json.dumps(x,ensure_ascii=False) for x in obj)
            return json.dumps(obj,ensure_ascii=False)
        except Exception:
            pass
    if ext == ".csv":
        # Preserve the original CSV header. CDR and financial parsers need
        # column names such as caller/receiver/duration and from/to/amount.
        return raw.decode("utf-8-sig",errors="replace").strip()
    return raw.decode("utf-8",errors="replace")

def record_date(rec):
    if rec.get("event_date"):
        return rec["event_date"]
    m=re.search(r"\b(20\d{2}-\d{2}-\d{2})\b", rec["text"])
    return m.group(1) if m else "2026-09-01"

def extract_amounts(text):
    return [float(m.group(1).replace(',','')) for m in re.finditer(r"(?:₹|INR|Rs\.?|Rupees)\s*([\d,]+(?:\.\d+)?)",text,re.I)]


def parse_cdr(text):
    rows=[]
    try:
        reader=csv.DictReader(io.StringIO(text))
        if reader.fieldnames:
            fields={f.strip().lower():f for f in reader.fieldnames if f}
            caller=fields.get("caller") or fields.get("from") or fields.get("source")
            receiver=fields.get("receiver") or fields.get("to") or fields.get("target")
            duration=fields.get("duration") or fields.get("duration_seconds") or fields.get("seconds")
            datef=fields.get("date") or fields.get("timestamp") or fields.get("datetime")
            if caller and receiver:
                for row in reader:
                    a=str(row.get(caller,'')).strip(); b=str(row.get(receiver,'')).strip()
                    if re.fullmatch(r'[6-9]\d{9}',a) and re.fullmatch(r'[6-9]\d{9}',b):
                        try: sec=float(row.get(duration,0) or 0) if duration else 0
                        except: sec=0
                        rows.append({'caller':a,'receiver':b,'duration_seconds':sec,'date':str(row.get(datef,'')).strip() if datef else ''})
    except Exception:
        pass
    # Lightweight fallback for synthetic narrative CDR notes.
    if not rows:
        for m in re.finditer(r'\b(?:phone\s*)?([6-9]\d{9})\b.{0,80}?(?:communicated with|called|contacted)\s+(?:phone\s*)?([6-9]\d{9})\b', text, re.I):
            rows.append({'caller':m.group(1),'receiver':m.group(2),'duration_seconds':0,'date':''})
        for m in re.finditer(r'\b([6-9]\d{9})\b.{0,50}?(?:communicated with|called|contacted)\s+(?:phone\s*)?([6-9]\d{9})\b', text, re.I):
            item={'caller':m.group(1),'receiver':m.group(2),'duration_seconds':0,'date':''}
            if item not in rows: rows.append(item)
    return rows

def case_records(case_id=DEFAULT_CASE_ID):
    return [r for r in records if r.get("case_id", DEFAULT_CASE_ID) == case_id]

def financial_person_links(case_id=DEFAULT_CASE_ID):
    """Resolve person/account links only when both occur in the same source sentence."""
    links = {}
    for r in case_records(case_id):
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", r.get("text", "")):
            ents = extract_entities(sentence)
            people = [e["label"] for e in ents if e["type"] == "PERSON"]
            accounts = [e["label"] for e in ents if e["type"] == "ACCOUNT"]
            for person in people:
                for account in accounts:
                    links.setdefault(person, set()).add(account)
    return {k: sorted(v) for k, v in links.items()}

def financial_transactions(case_id=DEFAULT_CASE_ID):
    transfers=[]
    for r in case_records(case_id):
        text=r.get('text','')
        if r.get('type')!='FINANCIAL':
            continue
        for m in re.finditer(r'(?:FROM|from)\s+(AC[-_]?\d{6,14})\s+(?:TO|to)\s+(AC[-_]?\d{6,14}).{0,120}?(?:₹|INR|Rs\.?|Rupees)\s*([\d,]+(?:\.\d+)?)',text):
            transfers.append({'from':m.group(1),'to':m.group(2),'amount':float(m.group(3).replace(',','')),'record':r['id']})
        parsed=parse_financial_csv(text)
        transfers.extend([{**x,'record':r['id']} for x in parsed])
    return transfers

def cdr_payload(case_id=DEFAULT_CASE_ID):
    calls=[]
    for r in case_records(case_id):
        if r.get('type')=='CDR':
            calls.extend(parse_cdr(r.get('text','')))
    pair=Counter(); duration=Counter(); days=Counter()
    for c in calls:
        key=tuple(sorted((c['caller'],c['receiver'])))
        pair[key]+=1; duration[key]+=c['duration_seconds']
        if c.get('date'): days[c['date']]+=1
    links=[{'caller':a,'receiver':b,'calls':n,'total_duration_seconds':round(duration[(a,b)],1)} for (a,b),n in pair.items()]
    links.sort(key=lambda x:(-x['calls'],-x['total_duration_seconds']))
    flags=[{'pair':f'{pair_key[0]} ↔ {pair_key[1]}','calls':n,'reason':'Repeated communication link','severity':'MEDIUM'} for pair_key,n in pair.items() if n>=2]
    return {'calls':len(calls),'unique_numbers':len(set([x for c in calls for x in (c['caller'],c['receiver'])])),'total_duration_seconds':round(sum(c['duration_seconds'] for c in calls),1),'links':links[:100],'flags':flags[:50],'daily':dict(sorted(days.items()))}

def rebuild():
    graph.clear()
    for case in cases.values():
        graph.add_node(norm_id("CASE", case["id"]), label=case["title"], type="CASE", case_id=case["id"])
    for rec in records:
        case_id=rec.get("case_id", DEFAULT_CASE_ID)
        if case_id not in cases:
            cases[case_id]={"id":case_id,"title":case_id,"status":"OPEN","description":"Imported case"}
            graph.add_node(norm_id("CASE", case_id),label=case_id,type="CASE",case_id=case_id)
        case_node=norm_id("CASE",case_id)
        event_node=norm_id("EVENT",rec["id"])
        graph.add_node(event_node,label=rec["id"],type="EVENT",record=rec["id"],date=record_date(rec),case_id=case_id)
        graph.add_edge(case_node,event_node,record=rec["id"],type="CONTAINS")
        ents=extract_entities(rec["text"])
        for e in ents:
            graph.add_node(e["id"],label=e["label"],type=e["type"])
            graph.add_edge(event_node,e["id"],record=rec["id"],type="MENTIONS")
        # Generic evidence co-occurrence for FIR/report/surveillance records.
        if rec.get("type") != "CDR" and rec.get("type") != "FINANCIAL":
            for a,b in combinations(ents,2):
                graph.add_edge(a["id"],b["id"],record=rec["id"],type=rec["type"])
                graph.add_edge(b["id"],a["id"],record=rec["id"],type=rec["type"])
            # Add explainable AI-extracted relationship edges in addition to
            # generic co-occurrence. These edges always point back to the
            # source record and are candidate relationships for investigator review.
            ent_by_label={e["label"].casefold():e for e in ents}
            for rel in ai_text_analysis(rec["text"])["relationships"]:
                a=ent_by_label.get(rel["source"].casefold())
                b=ent_by_label.get(rel["target"].casefold())
                if a and b and a["id"] != b["id"]:
                    graph.add_edge(a["id"],b["id"],record=rec["id"],type="AI_RELATIONSHIP",relationship_type=rel["type"],evidence=rel["evidence"])
        # CDR creates communication edges and, for narrative CDR notes, links
        # named people to the phone identifiers mentioned in the same evidence.
        if rec.get("type") == "CDR":
            for c in parse_cdr(rec.get("text","")):
                a=norm_id("PHONE",c["caller"]); b=norm_id("PHONE",c["receiver"])
                graph.add_node(a,label=c["caller"],type="PHONE"); graph.add_node(b,label=c["receiver"],type="PHONE")
                graph.add_edge(a,b,record=rec["id"],type="CDR",duration_seconds=c.get("duration_seconds",0),date=c.get("date",""))
            # Narrative CDR: preserve explicit person ↔ phone associations.
            for e in extract_entities(rec.get("text","")):
                graph.add_node(e["id"],label=e["label"],type=e["type"])
            phones=[e for e in extract_entities(rec.get("text","")) if e["type"]=="PHONE"]
            people=[e for e in extract_entities(rec.get("text","")) if e["type"]=="PERSON"]
            for p in people:
                for ph in phones:
                    graph.add_edge(p["id"],ph["id"],record=rec["id"],type="CDR_ASSOCIATION")
        # Financial records create money-flow edges and connect explicitly
        # referenced people/accounts into the same investigation graph.
        if rec.get("type") == "FINANCIAL":
            for t in parse_financial_csv(rec.get("text","")):
                a=norm_id("ACCOUNT",t["from"]); b=norm_id("ACCOUNT",t["to"])
                graph.add_node(a,label=t["from"],type="ACCOUNT"); graph.add_node(b,label=t["to"],type="ACCOUNT")
                graph.add_edge(a,b,record=rec["id"],type="FINANCIAL",amount=t.get("amount",0),date=t.get("date",""))
            ents_fin=extract_entities(rec.get("text",""))
            for e in ents_fin:
                graph.add_node(e["id"],label=e["label"],type=e["type"])
            people=[e for e in ents_fin if e["type"]=="PERSON"]
            accounts=[e for e in ents_fin if e["type"]=="ACCOUNT"]
            orgs=[e for e in ents_fin if e["type"]=="ORG"]
            for p in people:
                for a in accounts:
                    graph.add_edge(p["id"],a["id"],record=rec["id"],type="PERSON_ACCOUNT")
            for o in orgs:
                for a in accounts:
                    graph.add_edge(o["id"],a["id"],record=rec["id"],type="ORG_ACCOUNT")



def ai_text_analysis(text):
    """Lightweight, explainable NLP-style extraction for the demo; no guilt inference."""
    entities=extract_entities(text)
    relationships=[]
    rules=[
        (r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s+(?:is\s+)?associated\s+with\s+([^.,;\n]+)', 'ASSOCIATED_WITH'),
        (r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s+(?:met|contacted|called)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})', 'INTERACTED_WITH'),
        (r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\s+(?:was|were)\s+(?:seen|located)\s+(?:near|at)\s+([^.,;\n]+)', 'LOCATED_AT'),
    ]
    for pattern, rel_type in rules:
        for m in re.finditer(pattern, text):
            a,b=m.group(1).strip(),m.group(2).strip()
            relationships.append({'source':a,'target':b,'type':rel_type,'evidence':m.group(0).strip()[:180]})
    events=[]
    for m in re.finditer(r'\b(20\d{2}-\d{2}-\d{2})\b', text):
        events.append({'date':m.group(1),'text':text[max(0,m.start()-80):m.end()+120].strip()[:240]})
    amounts=extract_amounts(text)
    return {'entities':entities,'relationships':relationships,'events':events,'amounts':amounts,
            'summary':f'Extracted {len(entities)} entities, {len(relationships)} candidate relationships, {len(events)} dated event(s), and {len(amounts)} financial mention(s).',
            'disclaimer':'AI-style extraction is a review aid. Validate extracted entities and relationships against source evidence.'}

def unified_investigation_payload(case_id=DEFAULT_CASE_ID):
    """Cross-modal prioritization for demo data; not a guilt/criminality score."""
    g=simple_graph()
    if not g.nodes:
        return {"ranked":[],"signals":[],"connections":[],"stats":{"nodes":0,"connections":0}}
    degree=nx.degree_centrality(g)
    between=nx.betweenness_centrality(g,normalized=True)
    cdr=cdr_payload(case_id)
    fin=financial_analysis(case_id)
    person_accounts=fin.get("person_account_links", {})
    cdr_by_phone=Counter();
    for link in cdr.get("links",[]):
        cdr_by_phone[link["caller"]]+=link["calls"]
        cdr_by_phone[link["receiver"]]+=link["calls"]
    fin_by_account=Counter()
    for t in fin.get("transfers",[]):
        fin_by_account[t["from"]]+=float(t.get("amount",0))
        fin_by_account[t["to"]]+=float(t.get("amount",0))
    max_calls=max(cdr_by_phone.values(),default=1)
    max_money=max(fin_by_account.values(),default=1)
    ranked=[]
    for n,d in g.nodes(data=True):
        label=d.get("label",n); typ=d.get("type","UNKNOWN")
        network=min(100,(.55*degree.get(n,0)+.45*between.get(n,0))*100)
        comm=100*cdr_by_phone.get(label,0)/max_calls if typ=="PHONE" else 0
        money=100*fin_by_account.get(label,0)/max_money if typ=="ACCOUNT" else 0
        linked_accounts = person_accounts.get(label, []) if typ=="PERSON" else []
        linked_finance = sum(fin_by_account.get(a,0) for a in linked_accounts)
        money = max(money, 100*linked_finance/max_money) if linked_finance and max_money else money
        score=min(100,0.55*network+0.25*comm+0.20*money)
        reasons=[]
        if network >= 20: reasons.append("meaningful network connectivity")
        if comm > 0: reasons.append(f"CDR activity ({cdr_by_phone.get(label,0)} call(s))")
        if money > 0:
            value = linked_finance if typ == "PERSON" and linked_finance else fin_by_account.get(label,0)
            reasons.append(f"financial activity (INR {value:,.0f} aggregate linked value)")
        if linked_accounts:
            reasons.append("linked financial account(s): " + ", ".join(linked_accounts))
        if not reasons: reasons.append("baseline graph presence")
        modalities=[]
        if network > 0: modalities.append("NETWORK")
        if comm > 0: modalities.append("CDR")
        if money > 0: modalities.append("FINANCIAL")
        ranked.append({"id":n,"label":label,"type":typ,"network_score":round(network,2),"cdr_signal":round(comm,2),"financial_signal":round(money,2),"priority_score":round(score,2),"reasons":reasons,"modalities":modalities})
    ranked.sort(key=lambda x:x["priority_score"],reverse=True)
    connections=[]
    for u,v,data in graph.edges(data=True):
        connections.append({"source":graph.nodes[u].get("label",u),"target":graph.nodes[v].get("label",v),"source_type":graph.nodes[u].get("type"),"target_type":graph.nodes[v].get("type"),"evidence_type":data.get("type"),"record":data.get("record")})
    signals=[]
    if cdr.get("flags"):
        signals.append({"title":"Repeated communication","severity":"MEDIUM","detail":f"{len(cdr['flags'])} repeated CDR link(s) detected; verify against authorized records."})
    if fin.get("flags"):
        signals.append({"title":"Financial activity","severity":"MEDIUM","detail":f"{len(fin['flags'])} transaction lead(s) detected; verify provenance and authorization."})
    person_cdr_fin=[]
    for person, accounts in person_accounts.items():
        node=norm_id("PERSON", person)
        if node in g:
            linked_phones=[x for x in g.neighbors(node) if g.nodes[x].get("type")=="PHONE"]
            cdr_hits=sum(cdr_by_phone.get(g.nodes[x].get("label",""),0) for x in linked_phones)
            fin_value=sum(fin_by_account.get(a,0) for a in accounts)
            if cdr_hits>0 and fin_value>0:
                person_cdr_fin.append({"person":person,"phones":[g.nodes[x].get("label") for x in linked_phones],"accounts":accounts,"calls":cdr_hits,"financial_value":fin_value})
    if person_cdr_fin:
        preview=person_cdr_fin[0]
        signals.append({"title":"Cross-modal person linkage","severity":"HIGH","detail":f"{preview['person']} has source-supported phone/ CDR activity and linked financial account activity (INR {preview['financial_value']:,.0f}); verify the underlying records."})
    return {"ranked":ranked[:25],"signals":signals,"connections":connections[:150],"stats":{"nodes":g.number_of_nodes(),"connections":g.number_of_edges(),"cdr_calls":cdr.get("calls",0),"financial_transactions":fin.get("count",0),"financial_total":fin.get("total",0)}}

def simple_graph(include_structural=False):
    """Project the evidence graph for analytics; Case/Event nodes are optional."""
    allowed=[(node,data) for node,data in graph.nodes(data=True) if include_structural or data.get("type") not in {"CASE","EVENT"}]
    g=nx.Graph(); g.add_nodes_from(allowed)
    for u,v in graph.edges():
        if u!=v and u in g and v in g: g.add_edge(u,v)
    return g

def analytics_payload():
    g=simple_graph()
    if not g.nodes: return {"ranked":[],"suspicious":[],"patterns":[],"stats":{}}
    degree=nx.degree_centrality(g); between=nx.betweenness_centrality(g,normalized=True)
    ranked=[]
    for n in g.nodes:
        if g.nodes[n].get("type") in {"CASE", "EVENT"}:
            continue
        d=g.degree(n); score=min(100,(.55*degree.get(n,0)+.45*between.get(n,0))*100)
        ranked.append({"id":n,"label":g.nodes[n].get("label",n),"type":g.nodes[n].get("type","UNKNOWN"),"degree":d,"betweenness":round(between.get(n,0),4),"risk_score":round(score,2)})
    ranked.sort(key=lambda x:x["risk_score"],reverse=True)
    suspicious=[]
    for x in ranked:
        if x["type"]=="PERSON" and x["degree"]>=3:
            suspicious.append({"entity":x["label"],"score":x["risk_score"],"reason":"High network connectivity","explanation":"Connected to several distinct synthetic entities; this is an investigative lead, not a finding of guilt."})
        if x["type"] in {"PHONE","VEHICLE","ACCOUNT","EMAIL"} and x["degree"]>=2:
            suspicious.append({"entity":x["label"],"score":x["risk_score"],"reason":f"Shared {x['type'].lower()} identifier","explanation":"An identifier is linked to multiple entities and may merit verification."})
    patterns=[]
    for node,data in g.nodes(data=True):
        ns=list(g.neighbors(node)); types=Counter(g.nodes[n].get("type") for n in ns)
        if data.get("type")=="PERSON" and types["PHONE"] and types["VEHICLE"] and types["LOCATION"]:
            patterns.append({"title":"Multi-modal link","entity":data.get("label"),"severity":"MEDIUM","detail":"Person connected to phone, vehicle and location entities."})
    pair_counts=Counter()
    for rec in records:
        people=[e["label"] for e in extract_entities(rec["text"]) if e["type"]=="PERSON"]
        for pair in combinations(sorted(set(people)),2): pair_counts[pair]+=1
    for pair,count in pair_counts.items():
        if count>=2: patterns.append({"title":"Repeated co-occurrence","entity":" ↔ ".join(pair),"severity":"MEDIUM","detail":f"The pair appears together in {count} synthetic records."})
    for rec in records:
        amounts=extract_amounts(rec["text"])
        if amounts: patterns.append({"title":"Financial mention","entity":rec["id"],"severity":"LOW","detail":f"Detected {len(amounts)} amount mention(s), total ₹{sum(amounts):,.2f}. Verify against authorized financial records."})
    amounts=sum((extract_amounts(r["text"]) for r in records),[])
    stats={"entities":g.number_of_nodes(),"relationships":g.number_of_edges(),"people":sum(1 for _,d in g.nodes(data=True) if d.get("type")=="PERSON"),"records":len(records),"financial_mentions":len(amounts),"financial_total":round(sum(amounts),2),"locations":sum(1 for _,d in g.nodes(data=True) if d.get("type")=="LOCATION"),"phones":sum(1 for _,d in g.nodes(data=True) if d.get("type")=="PHONE"),"vehicles":sum(1 for _,d in g.nodes(data=True) if d.get("type")=="VEHICLE"),"organizations":sum(1 for _,d in g.nodes(data=True) if d.get("type")=="ORG"),"accounts":sum(1 for _,d in g.nodes(data=True) if d.get("type")=="ACCOUNT")}
    return {"ranked":ranked[:50],"suspicious":suspicious[:25],"patterns":patterns[:30],"stats":stats}

def community_payload():
    """Explainable community and anomaly signals for the synthetic evidence graph."""
    g=simple_graph()
    if not g.nodes:
        return {"communities":[],"assignments":[],"anomalies":[],"stats":{"communities":0,"anomalies":0}}
    components=[g.subgraph(nodes).copy() for nodes in nx.connected_components(g)]
    raw_communities=[]
    for component in components:
        if component.number_of_nodes() < 3:
            raw_communities.extend([{node} for node in component.nodes])
            continue
        try:
            raw_communities.extend(nx.community.louvain_communities(component, seed=42))
        except Exception:
            raw_communities.extend(nx.community.greedy_modularity_communities(component))
    raw_communities=sorted(raw_communities,key=lambda members:(-len(members),sorted(members)[0]))
    assignments=[]; communities=[]
    for index,members in enumerate(raw_communities,1):
        member_data=[{"id":node,"label":g.nodes[node].get("label",node),"type":g.nodes[node].get("type","UNKNOWN")} for node in sorted(members,key=lambda item:g.nodes[item].get("label",item))]
        communities.append({"id":index,"size":len(member_data),"members":member_data[:30]})
        assignments.extend([{**member,"community":index} for member in member_data])
    anomalies=[]
    betweenness=nx.betweenness_centrality(g,normalized=True)
    bridge_candidates=sorted(betweenness,key=betweenness.get,reverse=True)
    for node in bridge_candidates[:5]:
        score=betweenness[node]
        if score <= 0: continue
        anomalies.append({"kind":"BRIDGE_ENTITY","severity":"MEDIUM" if score < .2 else "HIGH","entity":g.nodes[node].get("label",node),"entity_id":node,"detail":f"Connects otherwise separate parts of the current evidence graph (betweenness {score:.2f}).","evidence_note":"Verify with the linked source records before drawing conclusions."})
    for node,data in g.nodes(data=True):
        degree=g.degree(node)
        if data.get("type") in {"PHONE","VEHICLE","ACCOUNT","EMAIL"} and degree >= 2:
            anomalies.append({"kind":"SHARED_IDENTIFIER","severity":"MEDIUM","entity":data.get("label",node),"entity_id":node,"detail":f"Shared {data.get('type','identifier').lower()} linked to {degree} graph entities.","evidence_note":"A shared identifier is an investigative lead, not proof of a relationship."})
    for flag in cdr_payload().get("flags",[]):
        anomalies.append({"kind":"REPEATED_CDR","severity":flag["severity"],"entity":flag["pair"],"entity_id":None,"detail":f"{flag['calls']} calls on the same communication link.","evidence_note":"Validate dates, call direction, and authorization."})
    for flag in financial_analysis().get("flags",[]):
        anomalies.append({"kind":"FINANCIAL_SIGNAL","severity":flag["severity"],"entity":f"{flag['from']} → {flag['to']}","entity_id":norm_id("ACCOUNT",flag["from"]),"detail":f"₹{flag['amount']:,.2f}: {flag['reason']}.","evidence_note":"Verify transaction provenance and legal authority."})
    seen=set(); unique=[]
    for signal in anomalies:
        key=(signal["kind"],signal["entity"])
        if key not in seen: seen.add(key); unique.append(signal)
    return {"communities":communities,"assignments":assignments,"anomalies":unique[:50],"stats":{"communities":len(communities),"anomalies":len(unique),"entities":g.number_of_nodes()}}

def write_audit(action, detail): audit_log.append({"time":datetime.now().isoformat(timespec="seconds"),"actor":ACTOR.get(),"action":action,"detail":detail})

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request):
    conn=_db(); row=conn.execute("SELECT username,password_hash,role,active FROM users WHERE username=?",(req.username.strip(),)).fetchone(); conn.close()
    if not row or not row["active"] or not _verify_password(req.password,row["password_hash"]):
        return JSONResponse({"detail":"Invalid username or password"},status_code=401)
    token=_make_session_token(row["username"], row["role"])
    write_audit("LOGIN_SUCCESS",f"{row['username']} authenticated as {row['role']}")
    response=JSONResponse({"ok":True,"username":row["username"],"role":row["role"]})
    response.set_cookie("netra_session",token,httponly=True,samesite="lax",secure=(request.url.scheme == "https"),max_age=8*60*60)
    return response

@app.get("/api/auth/me")
def me(request: Request):
    token=request.cookies.get("netra_session"); session=_read_session_token(token) if token else None
    if not session or session["expires"] < time.time(): raise HTTPException(401,"Authentication required")
    return {"authenticated":True,"username":session["username"],"role":session["role"]}

@app.post("/api/auth/logout")
def logout(request: Request):
    token=request.cookies.get("netra_session"); session=_read_session_token(token) if token else None
    if session: write_audit("LOGOUT",f"{session['username']} signed out")
    response=JSONResponse({"ok":True}); response.delete_cookie("netra_session"); return response

@app.get("/api/auth/users")
def auth_users():
    actor=ACTOR.get(); conn=_db(); me=conn.execute("SELECT role FROM users WHERE username=?",(actor,)).fetchone()
    if not me or me["role"]!="Administrator": conn.close(); raise HTTPException(403,"Administrator role required")
    rows=conn.execute("SELECT username,role,active FROM users ORDER BY username").fetchall(); conn.close(); return {"users":[dict(r) for r in rows]}

@app.get("/",response_class=HTMLResponse)
def index(): return (BASE/"app/static/index.html").read_text(encoding="utf-8")
@app.get("/api/records")
def get_records():
    return [{**r,"date":record_date(r),"entities":extract_entities(r["text"]),"amounts":extract_amounts(r["text"])} for r in records]
@app.post("/api/records")
def add_record(record:Record):
    if any(r["id"]==record.id for r in records): raise HTTPException(409,"Record ID already exists")
    if record.case_id not in cases: raise HTTPException(404,"Case not found")
    payload=record.model_dump(); payload["evidence_hash"]=calculate_evidence_hash(payload); records.append(payload); rebuild(); ents=extract_entities(record.text); write_audit("INGEST",f"Added {record.id} ({record.type})"); return {"ok":True,"entities":ents}

@app.get("/api/cases")
def get_cases():
    return [{**case,"record_count":sum(r.get("case_id",DEFAULT_CASE_ID)==case["id"] for r in records)} for case in cases.values()]

@app.post("/api/cases")
def add_case(case:Case):
    if case.id in cases: raise HTTPException(409,"Case ID already exists")
    cases[case.id]=case.model_dump(); rebuild(); write_audit("CASE_CREATED",f"Created {case.id}")
    return {"ok":True,"case":cases[case.id]}

@app.get("/api/cases/{case_id}")
def case_detail(case_id:str):
    if case_id not in cases: raise HTTPException(404,"Case not found")
    case_records=[r for r in records if r.get("case_id",DEFAULT_CASE_ID)==case_id]
    return {**cases[case_id],"records":[{**r,"date":record_date(r),"entities":extract_entities(r["text"])} for r in case_records]}
@app.post("/api/upload")
async def upload(file:UploadFile=File(...), category:str="AUTO"):
    if not file.filename: raise HTTPException(400,"Missing filename")
    raw=await file.read()
    if len(raw)>10*1024*1024: raise HTTPException(413,"File too large (max 10 MB)")
    content=decode_upload(file.filename,raw)
    if not content.strip(): raise HTTPException(400,"No readable text found in file")
    suffix=Path(file.filename).suffix.lower()
    category=(category or "AUTO").upper()
    if category in {"CDR","FINANCIAL","FIR","REPORT","SURVEILLANCE","INTELLIGENCE"}:
        rtype=category
    else:
        rtype="FIR" if suffix==".pdf" else ("CDR" if "cdr" in file.filename.lower() else ("FINANCIAL" if "financial" in file.filename.lower() or "transaction" in file.filename.lower() else "REPORT"))
    rec=Record(id=f"UPLOAD-{len(records)+1}",type=rtype,text=content); payload=rec.model_dump(); payload["evidence_hash"]=calculate_evidence_hash(payload); records.append(payload); rebuild(); ents=extract_entities(content); write_audit("UPLOAD",f"{file.filename} → {rtype}, {len(ents)} entities")
    return {"ok":True,"filename":file.filename,"record":rec.model_dump(),"entities":ents,"amounts":extract_amounts(content)}
@app.get("/api/graph")
def get_graph():
    edge_map={}
    for u,v,d in graph.edges(data=True):
        key=tuple(sorted((u,v)))
        edge_map.setdefault(key,{"source":key[0],"target":key[1],"records":[],"types":[]})
        edge_map[key]["records"].append(d.get("record")); edge_map[key]["types"].append(d.get("type"))
    edges=list(edge_map.values())
    for e in edges: e["records"]=sorted(set(e["records"])); e["types"]=sorted(set(e["types"])); e["weight"]=len(e["records"])
    return {"nodes":[{"id":n,**graph.nodes[n]} for n in graph.nodes],"edges":edges}
@app.get("/api/analytics")
def analytics(): return analytics_payload()
@app.get("/api/communities")
def communities(): return community_payload()
@app.get("/api/search")
def search(q:str=""):
    q=q.lower().strip(); return [] if not q else [{"id":n,**d} for n,d in graph.nodes(data=True) if q in d.get("label","").lower()][:30]

def edge_data_between(source, target):
    """Return all parallel directed edges from source to target in the evidence graph."""
    return list((graph.get_edge_data(source, target, default={}) or {}).values())

@app.get("/api/entity/{entity_id:path}")
def entity_detail(entity_id:str):
    if entity_id not in graph.nodes: raise HTTPException(404,"Entity not found")
    data=graph.nodes[entity_id]; related=[]; record_ids=set()
    for neighbor in set(graph.successors(entity_id)) | set(graph.predecessors(entity_id)):
        nd=graph.nodes[neighbor]; edge_records=[]
        for ed in edge_data_between(entity_id,neighbor)+edge_data_between(neighbor,entity_id):
            if ed.get("record"):
                edge_records.append(ed["record"]); record_ids.add(ed["record"])
        related.append({"id":neighbor,"label":nd.get("label"),"type":nd.get("type"),"records":sorted(set(edge_records))})
    evidence=[{**r,"date":record_date(r),"amounts":extract_amounts(r["text"])} for r in records if r["id"] in record_ids]
    return {"id":entity_id,**data,"related":sorted(related,key=lambda x:(x["type"],x["label"])),"evidence":evidence}

@app.get("/api/person/{person_id:path}/profile")
def person_profile(person_id:str):
    """Evidence-grounded 360° dossier for a PERSON node; never a guilt determination."""
    if person_id not in graph.nodes or graph.nodes[person_id].get("type") != "PERSON":
        raise HTTPException(404,"Person entity not found")
    detail=entity_detail(person_id)
    categories={"phones":[],"vehicles":[],"locations":[],"organizations":[],"accounts":[],"emails":[],"people":[]}
    category_for_type={"PHONE":"phones","VEHICLE":"vehicles","LOCATION":"locations","ORG":"organizations","ACCOUNT":"accounts","EMAIL":"emails","PERSON":"people"}
    for relation in detail["related"]:
        bucket=category_for_type.get(relation["type"])
        if bucket: categories[bucket].append(relation)
    linked_events=[]
    for event_id,event in graph.nodes(data=True):
        if event.get("type") != "EVENT": continue
        event_records={edge.get("record") for _,_,edge in graph.edges(event_id,data=True) if edge.get("record")}
        if any(record["id"] in event_records for record in detail["evidence"]):
            linked_events.append({"id":event_id,"label":event.get("label"),"date":event.get("date"),"case_id":event.get("case_id")})
    analytics=analytics_payload()
    score=next((item for item in analytics["ranked"] if item["id"]==person_id),None)

    # Cross-modal activity for identifiers linked to this person.
    # These are descriptive investigation signals, not guilt determinations.
    phone_labels={x["label"] for x in categories["phones"]}
    account_labels={x["label"] for x in categories["accounts"]}
    cdr_calls=[]
    for rec in records:
        if rec.get("type") != "CDR": continue
        for call in parse_cdr(rec.get("text","")):
            if call["caller"] in phone_labels or call["receiver"] in phone_labels:
                cdr_calls.append({**call,"record":rec["id"]})

    financial_links=[]
    for rec in records:
        text=rec.get("text","")
        if rec.get("type") == "FINANCIAL":
            for item in parse_financial_csv(text):
                if item["from"] in account_labels or item["to"] in account_labels:
                    financial_links.append({**item,"record":rec["id"]})
        for m in re.finditer(r'(?:FROM|from)\s+(?:account\s+)?(AC[-_]?\d{6,14})\s+(?:TO|to)\s+(?:account\s+)?(AC[-_]?\d{6,14}).{0,120}?(?:₹|INR|Rs\.?|Rupees)\s*([\d,]+(?:\.\d+)?)',text):
            item={"from":m.group(1),"to":m.group(2),"amount":float(m.group(3).replace(',','')),"record":rec["id"],"date":record_date(rec)}
            if item["from"] in account_labels or item["to"] in account_labels:
                financial_links.append(item)
        for m in re.finditer(r'(?:transaction|transfer).{0,80}?(?:₹|INR|Rs\.?|Rupees)\s*([\d,]+(?:\.\d+)?).{0,100}?(?:FROM|from)\s+(?:account\s+)?(AC[-_]?\d{6,14})\s+(?:TO|to)\s+(?:account\s+)?(AC[-_]?\d{6,14})',text,re.I):
            item={"from":m.group(2),"to":m.group(3),"amount":float(m.group(1).replace(',','')),"record":rec["id"],"date":record_date(rec)}
            if item["from"] in account_labels or item["to"] in account_labels:
                financial_links.append(item)
    financial_links=list({(x["from"],x["to"],x["amount"],x["record"]):x for x in financial_links}.values())
    cdr_minutes=round(sum(x.get("duration_seconds",0) for x in cdr_calls)/60,1)
    financial_total=round(sum(x.get("amount",0) for x in financial_links),2)

    reasons=[]
    if score:
        if score["degree"] >= 3: reasons.append(f"Connected to {score["degree"]} distinct graph entities")
        if score["betweenness"] > 0: reasons.append("Appears on relationship paths between other entities")
    if categories["phones"]: reasons.append(f"Linked to {len(categories["phones"])} phone identifier(s)")
    if categories["vehicles"]: reasons.append(f"Linked to {len(categories["vehicles"])} vehicle identifier(s)")
    if cdr_calls: reasons.append(f"Linked phone identifier(s) appear in {len(cdr_calls)} CDR call record(s)")
    if financial_links: reasons.append(f"Linked account identifier(s) appear in {len(financial_links)} financial transaction(s)")
    if not reasons: reasons.append("Profile is based on the currently linked synthetic evidence records")
    return {
        "person":{"id":person_id,"label":graph.nodes[person_id].get("label"),"type":"PERSON"},
        "case_ids":sorted({event["case_id"] for event in linked_events if event.get("case_id")}),
        "events":sorted(linked_events,key=lambda event:(event.get("date") or "",event["label"])),
        "identifiers":categories,
        "evidence":detail["evidence"],
        "priority":score,
        "snapshot":{"connections":len(detail["related"]),"evidence_records":len(detail["evidence"]),"linked_events":len(linked_events),"cdr_calls":len(cdr_calls),"cdr_minutes":cdr_minutes,"financial_transactions":len(financial_links),"financial_total":financial_total},
        "communications":sorted(cdr_calls,key=lambda x:(x.get("date") or "",x.get("record") or ""))[:50],
        "financial_activity":sorted(financial_links,key=lambda x:(x.get("date") or "",x.get("record") or ""))[:50],
        "explanation":{"reasons":reasons,"disclaimer":"This is a synthetic-evidence investigation profile. Activity counts are descriptive signals for review, not findings of guilt or criminality."},
    }

@app.post("/api/ai/analyze")
def ai_analyze(request:AssistantRequest):
    if not request.query.strip(): raise HTTPException(400,"Enter text to analyze")
    return ai_text_analysis(request.query)

@app.post("/api/ai/ingest")
def ai_ingest(request:AIIngestRequest):
    """Commit reviewed AI-extracted source text into the selected synthetic case."""
    text=request.text.strip()
    if not text: raise HTTPException(400,"Enter text to ingest")
    if request.case_id not in cases: raise HTTPException(404,"Case not found")
    analysis=ai_text_analysis(text)
    record_id=request.record_id.strip() if request.record_id else f"AI-{len(records)+1:03d}"
    if any(r["id"]==record_id for r in records): raise HTTPException(409,"Record ID already exists")
    event_date=analysis["events"][0]["date"] if analysis["events"] else None
    rec=Record(id=record_id,type=request.record_type.strip() or "AI-REPORT",text=text,case_id=request.case_id,event_date=event_date)
    payload=rec.model_dump(); payload["evidence_hash"]=calculate_evidence_hash(payload)
    records.append(payload)
    rebuild()
    write_audit("AI_INGEST",f"Added reviewed AI-extracted evidence {record_id} to {request.case_id} ({len(analysis['entities'])} entities, {len(analysis['relationships'])} candidate relationships)")
    return {"ok":True,"record":rec.model_dump(),"analysis":analysis,"message":"Evidence added to the investigation graph. Candidate relationships remain review aids."}

@app.get("/api/security/evidence")
def evidence_integrity(case_id: str = DEFAULT_CASE_ID):
    ensure_evidence_hashes()
    rows=[]
    for r in case_records(case_id):
        current=calculate_evidence_hash(r)
        stored=r.get("evidence_hash") or current
        rows.append({"id":r["id"],"type":r.get("type"),"date":record_date(r),"hash":stored,"algorithm":"SHA-256","status":"VERIFIED" if stored==current else "CHANGED","entities":len(extract_entities(r.get("text","")))})
    return {"algorithm":"SHA-256","records":rows,"verified":sum(x["status"]=="VERIFIED" for x in rows),"changed":sum(x["status"]=="CHANGED" for x in rows)}

@app.post("/api/security/verify/{record_id}")
def verify_evidence(record_id: str):
    ensure_evidence_hashes()
    rec=next((r for r in records if r["id"]==record_id),None)
    if not rec: raise HTTPException(404,"Evidence record not found")
    current=calculate_evidence_hash(rec); stored=rec.get("evidence_hash")
    ok=bool(stored and stored==current)
    write_audit("INTEGRITY_VERIFY",f"{record_id}: {'VERIFIED' if ok else 'CHANGED'}")
    return {"id":record_id,"algorithm":"SHA-256","stored_hash":stored,"current_hash":current,"status":"VERIFIED" if ok else "CHANGED"}

@app.get("/api/timeline")
def timeline():
    out=[]
    for r in records:
        ents=extract_entities(r["text"]); out.append({"id":r["id"],"type":r["type"],"date":record_date(r),"entity_count":len(ents),"entities":[e["label"] for e in ents],"amounts":extract_amounts(r["text"]),"preview":r["text"][:240]})
    return sorted(out,key=lambda x:(x["date"],x["id"]))

@app.get("/api/path")
def connection_path(source:str, target:str):
    """Return a shortest evidence-backed path; accepts internal IDs or entity labels."""
    def resolve(reference):
        reference=reference.strip()
        if reference in graph.nodes: return reference
        exact=[node for node,data in graph.nodes(data=True) if data.get("label","").casefold()==reference.casefold()]
        if len(exact)==1: return exact[0]
        partial=[node for node,data in graph.nodes(data=True) if reference.casefold() in data.get("label","").casefold()]
        if len(partial)==1: return partial[0]
        return None
    source_id=resolve(source); target_id=resolve(target)
    if not source_id or not target_id:
        raise HTTPException(404,"One or both entity names were not found. Use an exact graph label, e.g. Rohan Mehta and Suresh Khan.")
    source,target=source_id,target_id
    if source==target: return {"found":True,"path":[{"id":source,**graph.nodes[source]}],"hops":0,"evidence_records":[]}
    undirected=simple_graph(include_structural=True)
    try:
        node_ids=nx.shortest_path(undirected,source,target)
    except nx.NetworkXNoPath:
        return {"found":False,"path":[],"hops":0,"evidence_records":[]}
    evidence=set()
    for a,b in zip(node_ids,node_ids[1:]):
        for edge in edge_data_between(a,b)+edge_data_between(b,a):
            if edge.get("record"): evidence.add(edge["record"])
    return {"found":True,"path":[{"id":node_id,**graph.nodes[node_id]} for node_id in node_ids],"hops":len(node_ids)-1,"evidence_records":sorted(evidence)}

@app.post("/api/assistant")
def investigation_assistant(request:AssistantRequest):
    """Rule-routed, evidence-grounded assistant for the current synthetic case graph."""
    query=request.query.strip()
    if not query: raise HTTPException(400,"Enter an investigation question")
    q=query.casefold()
    entity_matches=[]
    for node,data in graph.nodes(data=True):
        if data.get("type") in {"CASE","EVENT"}: continue
        label=data.get("label","").casefold()
        person_token_match=data.get("type")=="PERSON" and any(len(token)>=3 and token in q for token in label.split())
        if label in q or person_token_match: entity_matches.append((node,data))
    suggestions=[
        "Rohan Mehta aur Suresh Khan ka shortest path dikhao",
        "Highest priority entities kaunse hain aur kyu?",
        "CDR repeated links batao",
        "Financial anomalies summarize karo",
        "Network communities batao",
    ]
    def response(intent,answer,evidence=[]):
        return {"intent":intent,"answer":answer,"evidence_records":sorted(set(evidence)),"disclaimer":"Synthetic evidence analysis only. This is an investigative lead, not a finding of guilt.","suggested_queries":suggestions}
    path_terms=("path","connection","between","beech","shortest")
    if any(term in q for term in path_terms) and len(entity_matches)>=2:
        first,second=entity_matches[0][0],entity_matches[1][0]
        result=connection_path(first,second)
        if not result["found"]:
            return response("PATH",f"No current graph path was found between {graph.nodes[first]['label']} and {graph.nodes[second]['label']}.")
        labels=" → ".join(item["label"] for item in result["path"])
        return response("PATH",f"Shortest evidence path ({result['hops']} hops): {labels}.",result["evidence_records"])
    if any(term in q for term in ("profile","dossier","person","details")) and entity_matches:
        person=next(((node,data) for node,data in entity_matches if data.get("type")=="PERSON"),None)
        if person:
            profile=person_profile(person[0]); ids=profile["identifiers"]
            summary=", ".join(f"{len(ids[key])} {key}" for key in ("phones","vehicles","locations","organizations","accounts") if ids[key]) or "no direct identifiers"
            return response("PROFILE",f"{profile['person']['label']} is linked to {summary}; {len(profile['events'])} event(s) and {len(profile['evidence'])} evidence record(s).",[record["id"] for record in profile["evidence"]])
    if any(term in q for term in ("case","record","evidence","document")):
        case_list=get_cases()
        summary="; ".join(f"{case['id']} ({case['title']}, {case['record_count']} records)" for case in case_list)
        return response("CASES",f"Available investigation cases: {summary}.",[record["id"] for record in records])
    if entity_matches:
        node,data=entity_matches[0]
        detail=entity_detail(node)
        related=detail["related"]
        locations=[item["label"] for item in related if item["type"]=="LOCATION"]
        if any(term in q for term in ("location","place","jagah","kahan","kahaan","where")):
            return response("LOCATION",f"{data['label']} is directly linked to: {', '.join(locations) or 'no location entity in the current graph' }.",[record["id"] for record in detail["evidence"]])
        if data.get("type")=="PERSON":
            profile=person_profile(node); ids=profile["identifiers"]
            linked=", ".join(f"{len(ids[key])} {key}" for key in ("phones","vehicles","locations","organizations","accounts") if ids[key]) or "no direct identifiers"
            return response("PERSON_CONNECTIONS",f"{data['label']} has {len(related)} direct graph connection(s): {linked}. Linked evidence records: {', '.join(record['id'] for record in detail['evidence']) or 'none'}.",[record["id"] for record in detail["evidence"]])
        return response("ENTITY_CONNECTIONS",f"{data['label']} ({data.get('type')}) has {len(related)} direct graph connection(s): {', '.join(item['label'] for item in related[:12]) or 'none'}.",[record["id"] for record in detail["evidence"]])
    if any(term in q for term in ("cdr","call","communication","phone")):
        cdr=cdr_payload(); evidence=[record["id"] for record in records if record.get("type")=="CDR"]
        lead=f" Repeated links: {len(cdr['flags'])}." if cdr["flags"] else " No repeated-link signal is currently detected."
        return response("CDR",f"CDR analysis contains {cdr['calls']} call(s) across {cdr['unique_numbers']} number(s), with {round(cdr['total_duration_seconds']/60)} total minute(s).{lead}",evidence)
    if any(term in q for term in ("financial","finance","money","transaction","account")):
        financial=financial_analysis(); evidence=[record["id"] for record in records if record.get("type")=="FINANCIAL"]
        return response("FINANCIAL",f"Financial analysis contains {financial['count']} transaction(s) totalling ₹{financial['total']:,.2f} across {financial['accounts']} account(s), with {len(financial['flags'])} investigation lead(s).",evidence)
    if any(term in q for term in ("community","cluster","anomal","bridge","group")):
        communities=community_payload(); bridge=[item["entity"] for item in communities["anomalies"] if item["kind"]=="BRIDGE_ENTITY"]
        return response("COMMUNITY",f"The graph has {communities['stats']['communities']} community cluster(s) and {communities['stats']['anomalies']} lead(s). Bridge candidates: {', '.join(bridge[:3]) or 'none detected'}.")
    analytics=analytics_payload(); top=analytics["ranked"][:3]
    if any(term in q for term in ("priority","rank","top","why","risk")):
        ranking="; ".join(f"{item['label']} ({item['risk_score']}, {item['degree']} links)" for item in top)
        return response("PRIORITY",f"Highest current graph-priority entities are {ranking}. Scores combine graph connectivity and betweenness, and require evidence review.")
    lead=", ".join(item["label"] for item in top) if top else "no entities"
    return response("SUMMARY",f"Current synthetic case graph: {analytics['stats']['entities']} entities, {analytics['stats']['relationships']} relationships, and {analytics['stats']['records']} records. Current top graph-priority entities: {lead}.")
@app.get("/api/locations")
def locations():
    out=[]
    for n,d in graph.nodes(data=True):
        if d.get("type")=="LOCATION":
            people=[graph.nodes[x]["label"] for x in graph.neighbors(n) if graph.nodes[x].get("type")=="PERSON"]
            out.append({"label":d["label"],"people":sorted(set(people)),"connections":graph.degree(n)})
    return out
@app.get("/api/audit")
def get_audit(): return list(reversed(audit_log[-50:]))
@app.get("/api/cdr")
def cdr_analysis(): return cdr_payload()

@app.get("/api/financial")
def financial_analysis(case_id:str=DEFAULT_CASE_ID):
    transfers=financial_transactions(case_id)
    accounts=sorted(set([x['from'] for x in transfers]+[x['to'] for x in transfers]))
    high=[x for x in transfers if x['amount']>=100000]
    incoming=Counter(); outgoing=Counter()
    for x in transfers:
        outgoing[x['from']]+=x['amount']; incoming[x['to']]+=x['amount']
    circular=[]
    for x in transfers:
        if any(y['from']==x['to'] and y['to']==x['from'] for y in transfers):
            circular.append({'from':x['from'],'to':x['to'],'amount':x['amount'],'reason':'Two-way transfer pattern'})
    flags=[]
    for x in high[:50]: flags.append({'from':x['from'],'to':x['to'],'amount':x['amount'],'severity':'HIGH','reason':'High-value transfer'})
    flags.extend({'from':x['from'],'to':x['to'],'amount':x['amount'],'severity':'MEDIUM','reason':x['reason']} for x in circular[:50])
    return {'transfers':transfers,'count':len(transfers),'total':round(sum(x['amount'] for x in transfers),2),'accounts':len(accounts),'incoming':dict(incoming),'outgoing':dict(outgoing),'flags':flags[:100],'top_accounts':sorted([{'account':a,'incoming':round(incoming[a],2),'outgoing':round(outgoing[a],2),'net':round(incoming[a]-outgoing[a],2)} for a in accounts],key=lambda x:abs(x['net']),reverse=True)[:30], 'person_account_links':financial_person_links(case_id)}

def parse_financial_csv(text):
    out=[]
    try:
        reader=csv.DictReader(io.StringIO(text))
        if not reader.fieldnames: return out
        fields={f.strip().lower():f for f in reader.fieldnames if f}
        ffrom=fields.get('from') or fields.get('source') or fields.get('sender')
        fto=fields.get('to') or fields.get('target') or fields.get('receiver')
        famt=fields.get('amount') or fields.get('value') or fields.get('amount_inr')
        fdate=fields.get('date') or fields.get('timestamp')
        if not ffrom or not fto or not famt: return out
        for row in reader:
            a=str(row.get(ffrom,'')).strip(); b=str(row.get(fto,'')).strip()
            if not a or not b: continue
            try: amount=float(re.sub(r'[^0-9.]','',str(row.get(famt,''))))
            except: continue
            if amount>0: out.append({'from':a,'to':b,'amount':amount,'date':str(row.get(fdate,'')).strip() if fdate else ''})
    except Exception: pass
    return out


@app.get("/api/investigation")
def investigation():
    rebuild()
    return unified_investigation_payload()



@app.post("/api/investigation/report/focus")
def set_report_focus(request: ReportFocusRequest):
    if request.case_id not in cases:
        raise HTTPException(404, "Case not found")
    valid=[]
    for entity_id in request.entity_ids[:30]:
        if entity_id in graph.nodes and graph.nodes[entity_id].get("type") not in {"CASE","EVENT"}:
            valid.append(entity_id)
    report_focus[request.case_id]=valid
    write_audit("REPORT_FOCUS", f"Selected {len(valid)} entity focus item(s) for {request.case_id}")
    return {"ok":True,"case_id":request.case_id,"entity_ids":valid,"labels":[graph.nodes[x].get("label",x) for x in valid]}


def build_investigation_report(case_id=DEFAULT_CASE_ID):
    """Build an evidence-grounded case report from the current in-memory investigation."""
    if case_id not in cases:
        raise HTTPException(404, "Case not found")
    rebuild()
    case=cases[case_id]
    case_records=[r for r in records if r.get("case_id",DEFAULT_CASE_ID)==case_id]
    a=analytics_payload()
    u=unified_investigation_payload()
    cdr=cdr_payload()
    fin=financial_analysis()
    timeline_items=[]
    for r in case_records:
        ents=extract_entities(r.get("text",""))
        timeline_items.append({"id":r["id"],"type":r.get("type","REPORT"),"date":record_date(r),"entities":[e["label"] for e in ents],"amounts":extract_amounts(r.get("text",""))})
    timeline_items.sort(key=lambda x:(x["date"],x["id"]))
    people=[]
    for n,d in graph.nodes(data=True):
        if d.get("type")=="PERSON":
            try:
                profile=person_profile(n)
                if case_id in profile["case_ids"] or not profile["case_ids"]:
                    people.append({"label":profile["person"]["label"],"priority":(profile.get("priority") or {}).get("risk_score",0),"snapshot":profile["snapshot"],"reasons":profile["explanation"]["reasons"]})
            except HTTPException:
                pass
    people.sort(key=lambda x:x["priority"],reverse=True)
    patterns=a.get("patterns",[])[:20]
    return {
        "case":case,
        "generated_at":datetime.now().isoformat(timespec="seconds"),
        "record_count":len(case_records),
        "records":[{"id":r["id"],"type":r.get("type"),"date":record_date(r),"preview":r.get("text","")[:500]} for r in case_records],
        "top_entities":u.get("ranked",[])[:10],
        "people_360":people[:10],
        "signals":u.get("signals",[]),
        "patterns":patterns,
        "timeline":timeline_items,
        "cdr":{"calls":cdr.get("calls",0),"unique_numbers":cdr.get("unique_numbers",0),"total_minutes":round(cdr.get("total_duration_seconds",0)/60,1),"repeated_links":len(cdr.get("flags",[]))},
        "financial":{"transactions":fin.get("count",0),"total":fin.get("total",0),"accounts":fin.get("accounts",0),"flags":fin.get("flags",[])[:20],"person_account_links":fin.get("person_account_links",{})},
        "cross_modal":u.get("signals",[]),
        "focus_entities":[{"id":x,"label":graph.nodes[x].get("label",x),"type":graph.nodes[x].get("type")} for x in report_focus.get(case_id,[]) if x in graph.nodes],
        "disclaimer":"Synthetic/demo evidence only. Automated signals are investigation aids and require human verification; they are not findings of guilt or criminality."
    }

@app.get("/api/investigation/report")
def investigation_report(case_id:str=DEFAULT_CASE_ID, format:str="json"):
    report=build_investigation_report(case_id)
    if format.lower() != "pdf":
        return report
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        fd,path=tempfile.mkstemp(prefix="trinetra_report_",suffix=".pdf"); os.close(fd)
        doc=SimpleDocTemplate(path,pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36)
        styles=getSampleStyleSheet()
        styles.add(ParagraphStyle(name="ReportTitle",parent=styles["Title"],alignment=TA_CENTER,spaceAfter=14))
        story=[Paragraph("NETRA — INVESTIGATION REPORT",styles["ReportTitle"]),Paragraph(f"Case: {report['case']['id']} — {report['case']['title']}",styles["Heading2"]),Paragraph(f"Generated: {report['generated_at']}",styles["Normal"]),Spacer(1,10),Paragraph(report["case"].get("description", ""),styles["Normal"]),Spacer(1,12)]
        story.append(Paragraph("Executive Summary",styles["Heading2"]))
        story.append(Paragraph(f"{report['record_count']} evidence record(s). Network/relationship intelligence produced {len(report['top_entities'])} ranked entities for review, with {len(report['signals'])} investigation signal(s).",styles["Normal"]))
        story.append(Spacer(1,10))
        story.append(Paragraph("Key Entities",styles["Heading2"]))
        data=[["Entity","Type","Priority","Signals"]]+[[x["label"],x["type"],str(x.get("priority_score",0)),"; ".join(x.get("reasons",[]))] for x in report["top_entities"]]
        if len(data)>1:
            t=Table(data,colWidths=[105,60,55,290],repeatRows=1); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.4,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey),("VALIGN",(0,0),(-1,-1),"TOP"),("FONTSIZE",(0,0),(-1,-1),8)])); story.append(t)
        story.append(Spacer(1,12)); story.append(Paragraph("Investigator Focus",styles["Heading2"]))
        if report.get("focus_entities"):
            story.append(Paragraph("Entities explicitly selected by the investigator for focused review:",styles["Normal"]))
            for item in report["focus_entities"]:
                story.append(Paragraph(f"{item['label']} ({item['type']})",styles["Normal"]))
        else:
            story.append(Paragraph("No entities were explicitly selected for focused review.",styles["Normal"]))
        story.append(Spacer(1,12)); story.append(Paragraph("CDR & Financial Summary",styles["Heading2"]))
        story.append(Paragraph(f"CDR: {report['cdr']['calls']} calls, {report['cdr']['unique_numbers']} unique numbers, {report['cdr']['total_minutes']} minutes, {report['cdr']['repeated_links']} repeated-link lead(s).",styles["Normal"]))
        story.append(Paragraph(f"Finance: {report['financial']['transactions']} transactions, INR {report['financial']['total']:,.2f} total, {report['financial']['accounts']} accounts, {len(report['financial']['flags'])} lead(s).",styles["Normal"]))
        story.append(Spacer(1,12)); story.append(Paragraph("Cross-Modal Investigation Leads",styles["Heading2"]))
        cross=[s for s in report.get("cross_modal",[]) if s.get("title")=="Cross-modal person linkage"]
        if cross:
            for sig in cross: story.append(Paragraph(f"{sig['severity']}: {sig['detail']}",styles["Normal"]))
        else:
            story.append(Paragraph("No source-supported person-level cross-modal linkage signal was detected in this case.",styles["Normal"]))
        story.append(Spacer(1,12)); story.append(Paragraph("People 360",styles["Heading2"]))
        for person in report["people_360"]:
            story.append(Paragraph(f"{person['label']} — priority {person['priority']}",styles["Heading3"]))
            story.append(Paragraph(" • ".join(person["reasons"]) or "No additional descriptive signals.",styles["Normal"]))
        story.append(Spacer(1,10)); story.append(Paragraph("Timeline",styles["Heading2"]))
        for item in report["timeline"]:
            story.append(Paragraph(f"{item['date']} — {item['id']} ({item['type']}) — {', '.join(item['entities'][:8])}",styles["Normal"]))
        story.append(Spacer(1,12)); story.append(Paragraph("Investigation Signals",styles["Heading2"]))
        for sig in report["signals"]:
            story.append(Paragraph(f"{sig['severity']}: {sig['title']} — {sig['detail']}",styles["Normal"]))
        story.append(Spacer(1,16)); story.append(Paragraph("Review & Disclaimer",styles["Heading2"]))
        story.append(Paragraph(report["disclaimer"],styles["Normal"]))
        doc.build(story)
        return FileResponse(path,media_type="application/pdf",filename=f"Netra_{case_id}_Investigation_Report.pdf",background=BackgroundTask(lambda: os.unlink(path) if os.path.exists(path) else None))
    except ImportError:
        raise HTTPException(500,"PDF export requires reportlab. Run: py -3.13 -m pip install reportlab")

@app.get("/api/summary")
def summary():
    a=analytics_payload(); top=a["ranked"][:3]; p=a["patterns"][:4]
    lead=', '.join(x['label'] for x in top) if top else 'No entities'
    return {"headline":"Synthetic intelligence summary","text":f"The current synthetic case graph contains {a['stats'].get('entities',0)} entities across {a['stats'].get('records',0)} records. Highest graph-priority entities are {lead}. {len(p)} pattern signal(s) were detected. These signals require investigator verification and are not conclusions of guilt.","top":top,"patterns":p}


# Include the bundled synthetic financial dataset in the demo case so the
# cross-modal workflow is visible immediately after a fresh restart.
SAMPLE_FINANCIAL_FILE = BASE / "data" / "sample_financial.csv"
if SAMPLE_FINANCIAL_FILE.exists() and not any(r.get("id") == "FIN-SAMPLE-001" for r in records):
    records.append(Record(id="FIN-SAMPLE-001", type="FINANCIAL", text=SAMPLE_FINANCIAL_FILE.read_text(encoding="utf-8").strip(), case_id=DEFAULT_CASE_ID).model_dump())

# Build the in-memory graph after all parser functions are defined.
ensure_evidence_hashes()
rebuild()
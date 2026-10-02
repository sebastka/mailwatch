// Check-specific details shown under the findings of each domain.
import type {
  BimiData,
  CertInfo,
  DaneData,
  DkimData,
  DmarcData,
  DmarcUri,
  DnsblData,
  DomainData,
  MtaStsData,
  MxData,
  SendersData,
  ServiceProbe,
  SpfData,
  SpfNode,
  TlsRptData,
} from '../../shared/types.ts';
import { ALGORITHMS } from '../../shared/dnssec.ts';
import { StatusPill } from '../components/ui.tsx';
import { ago, dateTime, daysUntil } from '../format.ts';

type DetailsProps = { data: unknown; domain: string };

const Yes = ({ ok, yes = 'yes', no = 'no' }: { ok: boolean | null; yes?: string; no?: string }) =>
  ok === null ? <span className="muted">–</span> : <StatusPill level={ok ? 'ok' : 'error'} text={ok ? yes : no} />;

function Record({ label, value }: { label: string; value: string | null }) {
  return (
    <>
      <div className="subhead">{label}</div>
      {value ? <div className="record">{value}</div> : <div className="muted">None published</div>}
    </>
  );
}

function Cert({ c }: { c: CertInfo }) {
  return (
    <span>
      {c.subject.replace(/^.*CN=/, '')}{' '}
      <span className="muted">
        by {c.issuer.replace(/^.*CN=/, '')}, until {c.validTo.slice(0, 10)} ({c.daysLeft} days)
      </span>
    </span>
  );
}

export function MxDetails({ data }: DetailsProps) {
  const d = data as MxData;
  return (
    <>
      <div className="subhead">
        MX records{' '}
        {d.dnssec ? (
          <StatusPill level="ok" text="DNSSEC-signed" />
        ) : (
          <span className="muted small">(not DNSSEC-signed)</span>
        )}
      </div>
      {d.nullMx ? (
        <div className="record">0 . (Null MX)</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th className="num">Pref.</th>
                <th>Host</th>
                <th>Address</th>
                <th>Reverse DNS</th>
              </tr>
            </thead>
            <tbody>
              {d.records.flatMap((r) =>
                (r.addresses.length ? r.addresses : [null]).map((a, i) => (
                  <tr key={`${r.exchange}-${a?.ip ?? i}`}>
                    <td className="num">{i === 0 ? r.preference : ''}</td>
                    <td className="mono">
                      {i === 0 && r.exchange}
                      {i === 0 && r.cname && <div className="muted">CNAME → {r.cname}</div>}
                      {i === 0 && d.implicit && <div className="muted">implicit (no MX record)</div>}
                    </td>
                    <td className="mono">{a?.ip ?? <span className="muted">no address</span>}</td>
                    <td className="mono">
                      {a?.ptr ?? <span className="muted">–</span>}{' '}
                      {a?.fcrdns === false && a.ptr && <span className="muted">(does not resolve back)</span>}
                    </td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        </div>
      )}
      <div className="subhead">SMTP on port 25</div>
      {!d.probeEnabled ? (
        <div className="muted">Probing is disabled (SMTP_PROBE=false).</div>
      ) : !d.smtp.length ? (
        <div className="muted">Nothing probed.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Banner</th>
                <th>STARTTLS</th>
                <th>TLS</th>
                <th>Certificate</th>
                <th>Trusted</th>
                <th>Name</th>
              </tr>
            </thead>
            <tbody>
              {d.smtp.map((p) => (
                <tr key={`${p.host}-${p.ip}`}>
                  <td className="mono">
                    {p.host}
                    <div className="muted">
                      {p.ip} · {p.durationMs} ms
                    </div>
                  </td>
                  <td className="mono" style={{ maxWidth: 260, overflowWrap: 'anywhere' }}>
                    {p.banner ?? <span className="muted">{p.error ?? '–'}</span>}
                    {p.extensions.length > 0 && <div className="muted">{p.extensions.join(' · ')}</div>}
                  </td>
                  <td>{p.connected ? <Yes ok={p.starttls} /> : <span className="muted">not connected</span>}</td>
                  <td className="mono">
                    {p.tls ? (
                      <>
                        {p.tls.protocol}
                        <div className="muted">{p.tls.cipher}</div>
                      </>
                    ) : (
                      <span className="muted">{p.starttls ? (p.error ?? '–') : '–'}</span>
                    )}
                  </td>
                  <td>{p.tls?.chain[0] ? <Cert c={p.tls.chain[0]} /> : <span className="muted">–</span>}</td>
                  <td>{p.tls ? <Yes ok={p.tls.authorized} /> : <span className="muted">–</span>}</td>
                  <td>
                    {p.tls ? (
                      <Yes ok={p.tls.hostnameMatch} yes="matches" no="mismatch" />
                    ) : (
                      <span className="muted">–</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function SpfTree({ node, root = false }: { node: SpfNode; root?: boolean }) {
  return (
    <ul className={`spf-tree${root ? ' root' : ''}`}>
      {node.terms.map((t, i) => (
        <li key={i}>
          {t.raw}
          {t.lookups > 0 && <span className="cost">1 lookup</span>}
          {t.child && (
            <>
              {t.child.error && <span className="delta-up small"> {t.child.error}</span>}
              {t.child.record && <SpfTree node={t.child} />}
            </>
          )}
        </li>
      ))}
    </ul>
  );
}

export function SpfDetails({ data }: DetailsProps) {
  const d = data as SpfData;
  return (
    <>
      <Record label="Record" value={d.record ?? (d.records.length ? d.records.join('\n') : null)} />
      {d.tree && (
        <>
          <div className="subhead">
            Evaluation tree · {d.lookups} of 10 DNS lookups · {d.voidLookups} void lookup
            {d.voidLookups === 1 ? '' : 's'}
          </div>
          <SpfTree node={d.tree} root />
          <div className="subhead">
            Authorised addresses ({d.ip4.length} IPv4, {d.ip6.length} IPv6 ranges)
          </div>
          <details className="collapsible">
            <summary className="small">Show</summary>
            <div className="record">{[...d.ip4, ...d.ip6].join('\n') || '(none)'}</div>
          </details>
        </>
      )}
    </>
  );
}

const SOURCE_LABEL: Record<string, string> = {
  configured: 'configured',
  reports: 'DMARC reports',
  delivery: 'delivery tests',
  common: 'common name',
};

export function DkimDetails({ data }: DetailsProps) {
  const d = data as DkimData;
  if (!d.selectors.length) return <div className="muted">No selector found.</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Selector</th>
            <th>Found via</th>
            <th>Key</th>
            <th>Flags</th>
            <th title="When MailWatch first saw this key: DNS has no publication date">Key seen since</th>
            <th>Record</th>
          </tr>
        </thead>
        <tbody>
          {d.selectors.map((s) => (
            <tr key={s.selector}>
              <td className="mono">
                {s.selector}
                {s.cname && <div className="muted">CNAME → {s.cname}</div>}
              </td>
              <td>{s.sources.map((x) => SOURCE_LABEL[x] ?? x).join(', ')}</td>
              <td>
                {!s.found ? (
                  <StatusPill level="error" text="missing" />
                ) : s.revoked ? (
                  <span className="muted">revoked</span>
                ) : (
                  <>
                    {s.keyType === 'ed25519' ? 'Ed25519' : 'RSA'} {s.keyBits ? `${s.keyBits} bit` : ''}
                  </>
                )}
              </td>
              <td>
                {[s.testing && 't=y (testing)', s.tags.h && `h=${s.tags.h}`, s.tags.s && `s=${s.tags.s}`]
                  .filter(Boolean)
                  .join(', ') || <span className="muted">–</span>}
              </td>
              <td title={s.keySince ? dateTime(s.keySince) : undefined}>
                {s.keySince ? s.keySince.slice(0, 10) : <span className="muted">–</span>}
              </td>
              <td className="mono" style={{ maxWidth: 360, overflowWrap: 'anywhere' }}>
                {s.record ? (
                  s.record.length > 120 ? (
                    `${s.record.slice(0, 120)}…`
                  ) : (
                    s.record
                  )
                ) : (
                  <span className="muted">–</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const DMARC_TAGS: Record<string, string> = {
  v: 'Version',
  p: 'Policy for the domain',
  sp: 'Policy for subdomains',
  np: 'Policy for non-existent subdomains (DMARCbis)',
  pct: 'Share of failing mail the policy applies to',
  adkim: 'DKIM alignment (r = relaxed, s = strict)',
  aspf: 'SPF alignment (r = relaxed, s = strict)',
  fo: 'When to send failure reports (0 = all fail, 1 = any fails, d = DKIM, s = SPF)',
  rf: 'Failure report format',
  ri: 'Aggregate report interval (seconds)',
  rua: 'Aggregate report addresses',
  ruf: 'Failure report addresses',
  t: 'Testing mode (DMARCbis)',
  psd: 'Public suffix domain (DMARCbis)',
};

function Destinations({ uris }: { uris: DmarcUri[] }) {
  if (!uris.length) return <span className="muted">none</span>;
  return (
    <>
      {uris.map((u) => (
        <div key={u.uri}>
          <span className="mono">{u.address ?? u.uri}</span>{' '}
          {u.problem && <StatusPill level="warning" text={`invalid: ${u.problem}`} />}
          {u.authorized === true && <StatusPill level="ok" text="external, authorised" />}
          {u.authorized === false && <StatusPill level="error" text="external, not authorised" />}
          {u.monitored && <StatusPill level="ok" text="read by MailWatch" />}
        </div>
      ))}
    </>
  );
}

export function DmarcDetails({ data }: DetailsProps) {
  const d = data as DmarcData;
  return (
    <>
      <Record label={d.name ? `_dmarc.${d.name}${d.inherited ? ' (inherited)' : ''}` : 'Record'} value={d.record} />
      {d.record && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Tag</th>
                <th>Value</th>
                <th>Meaning</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(d.tags).map(([k, v]) => (
                <tr key={k}>
                  <td className="mono">{k}</td>
                  <td className="mono" style={{ overflowWrap: 'anywhere' }}>
                    {k === 'rua' ? <Destinations uris={d.rua} /> : k === 'ruf' ? <Destinations uris={d.ruf} /> : v}
                  </td>
                  <td className="muted">{DMARC_TAGS[k] ?? 'Unknown tag'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

export function MtaStsDetails({ data }: DetailsProps) {
  const d = data as MtaStsData;
  return (
    <>
      <Record label="_mta-sts TXT" value={d.record} />
      {d.record && (
        <>
          <div className="subhead">Policy</div>
          <dl className="kv">
            <dt>URL</dt>
            <dd className="mono">
              <a href={d.policyUrl} target="_blank" rel="noreferrer">
                {d.policyUrl}
              </a>
            </dd>
            <dt>Response</dt>
            <dd>
              {d.fetch?.error ?? `HTTP ${d.fetch?.status ?? '?'}, ${d.fetch?.contentType ?? 'no content type'}`}
              {d.fetch?.redirect && <> → {d.fetch.redirect}</>}
            </dd>
            <dt>Certificate</dt>
            <dd>{d.fetch?.cert ? <Cert c={d.fetch.cert} /> : '–'}</dd>
          </dl>
          {d.raw !== null && <pre style={{ marginTop: 8 }}>{d.raw}</pre>}
          {d.coverage.length > 0 && (
            <>
              <div className="subhead">MX coverage</div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>MX</th>
                      <th>Matches a policy pattern</th>
                      <th>Valid certificate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {d.coverage.map((c) => (
                      <tr key={c.mx}>
                        <td className="mono">{c.mx}</td>
                        <td>
                          <Yes ok={c.matched} />
                        </td>
                        <td>
                          <Yes ok={c.certValid} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </>
  );
}

export function TlsRptDetails({ data }: DetailsProps) {
  const d = data as TlsRptData;
  return (
    <>
      <Record label="_smtp._tls TXT" value={d.record} />
      {d.rua.length > 0 && (
        <>
          <div className="subhead">Report destinations</div>
          <Destinations uris={d.rua} />
        </>
      )}
    </>
  );
}

const USAGE = ['PKIX-TA', 'PKIX-EE', 'DANE-TA', 'DANE-EE'];
const SELECTOR = ['full certificate', 'public key'];
const MATCHING = ['exact', 'SHA-256', 'SHA-512'];

export function DaneDetails({ data }: DetailsProps) {
  const d = data as DaneData;
  return (
    <>
      <dl className="kv">
        <dt>Domain signed</dt>
        <dd>
          <Yes ok={d.zoneSigned} />
        </dd>
        <dt>MX records validated</dt>
        <dd>
          <Yes ok={d.mxSecure} />
        </dd>
      </dl>
      {d.zone && (d.keys?.length || d.ds?.length) ? <DnssecDetails d={d} /> : null}
      {d.hosts.length > 0 && (
        <div className="table-wrap" style={{ marginTop: 10 }}>
          <table>
            <thead>
              <tr>
                <th>MX</th>
                <th>TLSA</th>
                <th>Meaning</th>
                <th>Data</th>
                <th>Matches certificate</th>
              </tr>
            </thead>
            <tbody>
              {d.hosts.flatMap((h) =>
                (h.tlsa.length ? h.tlsa : [null]).map((t, i) => (
                  <tr key={`${h.mx}-${i}`}>
                    <td className="mono">
                      {i === 0 && h.mx}
                      {i === 0 && h.tlsa.length > 0 && (
                        <div className="muted">{h.tlsaSecure ? 'TLSA validated' : 'TLSA not validated'}</div>
                      )}
                    </td>
                    <td className="mono">
                      {t ? `${t.usage} ${t.selector} ${t.matchingType}` : <span className="muted">none</span>}
                    </td>
                    <td>
                      {t
                        ? `${USAGE[t.usage] ?? '?'}, ${SELECTOR[t.selector] ?? '?'}, ${MATCHING[t.matchingType] ?? '?'}`
                        : ''}
                    </td>
                    <td className="mono" style={{ maxWidth: 280, overflowWrap: 'anywhere' }}>
                      {t ? (t.data.length > 64 ? `${t.data.slice(0, 64)}…` : t.data) : ''}
                    </td>
                    <td>{t ? h.probed ? <Yes ok={t.matched} /> : <span className="muted">not probed</span> : ''}</td>
                  </tr>
                )),
              )}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

const alg = (n: number) => ALGORITHMS[n] ?? `algorithm ${n}`;
const DIGEST = ['', 'SHA-1', 'SHA-256', 'GOST', 'SHA-384'];

function DnssecDetails({ d }: { d: DaneData }) {
  return (
    <>
      <div className="subhead">DNSSEC of {d.zone}</div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Record</th>
              <th className="num">Key tag</th>
              <th>Algorithm</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {(d.ds ?? []).map((x) => (
              <tr key={`ds-${x.keyTag}-${x.digestType}`}>
                <td>DS at the parent ({DIGEST[x.digestType] ?? `digest ${x.digestType}`})</td>
                <td className="num mono">{x.keyTag}</td>
                <td>{alg(x.algorithm)}</td>
                <td>
                  {x.matches === null ? (
                    <span className="muted">no such key</span>
                  ) : (
                    <Yes ok={x.matches} yes="matches the key" no="digest differs" />
                  )}
                </td>
              </tr>
            ))}
            {(d.keys ?? []).map((k) => (
              <tr key={`key-${k.keyTag}-${k.flags}`}>
                <td>DNSKEY ({k.flags === 257 ? 'key-signing' : 'zone-signing'})</td>
                <td className="num mono">{k.keyTag}</td>
                <td>{alg(k.algorithm)}</td>
                <td>
                  {k.matchedByDs ? (
                    <StatusPill level="ok" text="trusted by DS" />
                  ) : (
                    <span className="muted">{k.flags === 257 ? 'no DS' : '–'}</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {d.signatures && d.signatures.length > 0 && (
        <>
          <div className="subhead">Signatures</div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Covers</th>
                  <th className="num">Key tag</th>
                  <th>Signed</th>
                  <th>Expires</th>
                </tr>
              </thead>
              <tbody>
                {d.signatures.map((x) => (
                  <tr key={`${x.name}-${x.type}-${x.keyTag}`}>
                    <td className="mono">
                      {x.type} {x.name}
                    </td>
                    <td className="num mono">{x.keyTag}</td>
                    <td title={dateTime(x.inception)}>{x.inception.slice(0, 16).replace('T', ' ')}</td>
                    <td title={dateTime(x.expiration)}>
                      {x.expiration.slice(0, 16).replace('T', ' ')}{' '}
                      <span className="muted">({ago(x.expiration).replace(/ ago$/, '')})</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}

export function BimiDetails({ data }: DetailsProps) {
  const d = data as BimiData;
  return (
    <>
      <Record label="default._bimi TXT" value={d.record} />
      {d.record && (
        <dl className="kv">
          <dt>Logo (l=)</dt>
          <dd>
            {d.logo ? (
              <>
                <span className="mono">{d.logo.url}</span>
                <div className="muted">
                  {d.logo.error ?? `HTTP ${d.logo.status}, ${d.logo.contentType ?? '?'}, ${d.logo.bytes ?? '?'} bytes`}
                </div>
              </>
            ) : (
              '–'
            )}
          </dd>
          <dt>Mark certificate (a=)</dt>
          <dd>
            {d.authority ? (
              <>
                <span className="mono">{d.authority.url}</span>
                <div className="muted">{d.authority.error ?? `HTTP ${d.authority.status}`}</div>
              </>
            ) : (
              '–'
            )}
          </dd>
        </dl>
      )}
    </>
  );
}

export function DnsblDetails({ data }: DetailsProps) {
  const d = data as DnsblData;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Address / domain</th>
            <th>Used as</th>
            {d.zones.map((z) => (
              <th key={z} className="cell">
                {z}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {d.ips.map((ip) => (
            <tr key={ip.ip}>
              <td className="mono">{ip.ip}</td>
              <td className="small">{ip.sources.join(', ')}</td>
              {d.zones.map((z) => {
                const l = ip.listings.find((x) => x.zone === z);
                return (
                  <td key={z} className="cell" title={l?.reason ?? undefined}>
                    {!l ? (
                      <span className="muted">–</span>
                    ) : l.listed ? (
                      <StatusPill level="error" text="listed" />
                    ) : l.refused ? (
                      <span className="muted">unknown</span>
                    ) : (
                      <StatusPill level="ok" text="clean" />
                    )}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function DomainDetails({ data }: DetailsProps) {
  const d = data as DomainData;
  const r = d.registration;
  return (
    <>
      <div className="subhead">Registration of {d.zone}</div>
      {!r ? (
        <div className="muted">Not looked up (RDAP_CHECK=false).</div>
      ) : (
        <dl className="kv">
          <dt>Registrar</dt>
          <dd>{r.registrar ?? <span className="muted">–</span>}</dd>
          <dt>Registered</dt>
          <dd>{r.registered?.slice(0, 10) ?? <span className="muted">–</span>}</dd>
          <dt>Expires</dt>
          <dd>
            {r.expires ? (
              <>
                {r.expires.slice(0, 10)} <span className="muted">({daysUntil(r.expires)} days)</span>
              </>
            ) : (
              <span className="muted">not published by the registry</span>
            )}
          </dd>
          <dt>Last changed</dt>
          <dd>{r.lastChanged?.slice(0, 10) ?? <span className="muted">–</span>}</dd>
          <dt>Status</dt>
          <dd className="mono">{r.status.join(', ') || <span className="muted">–</span>}</dd>
          <dt>Delegation signed</dt>
          <dd>
            <Yes ok={r.delegationSigned} />
          </dd>
          <dt>Source</dt>
          <dd className="muted">
            {r.error ?? (
              <>
                <span className="mono">{r.server ?? 'no RDAP service'}</span>, fetched {ago(r.fetchedAt)}
              </>
            )}
          </dd>
        </dl>
      )}
      <div className="subhead">Nameservers</div>
      {!d.nameservers.length ? (
        <div className="muted">No NS records.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Nameserver</th>
                <th>Address</th>
                <th>Answer</th>
                <th className="num">SOA serial</th>
              </tr>
            </thead>
            <tbody>
              {d.nameservers.flatMap((n) => {
                const rows = n.probes.length
                  ? n.probes
                  : (n.addresses.length ? n.addresses : [null]).map((ip) => ({
                      ip,
                      rcode: null,
                      authoritative: null,
                      serial: null,
                    }));
                return rows.map((p, i) => (
                  <tr key={`${n.host}-${p.ip ?? i}`}>
                    <td className="mono">{i === 0 && n.host}</td>
                    <td className="mono">{p.ip ?? <span className="muted">no address</span>}</td>
                    <td>
                      {p.rcode === null ? (
                        <span className="muted">{d.probed ? '–' : 'not queried'}</span>
                      ) : p.rcode === 'NOERROR' && p.authoritative ? (
                        <StatusPill level="ok" text="authoritative" />
                      ) : (
                        <StatusPill
                          level={p.rcode === 'NOERROR' ? 'error' : 'warning'}
                          text={p.rcode === 'NOERROR' ? 'not authoritative' : p.rcode}
                        />
                      )}
                    </td>
                    <td className="num mono">{p.serial ?? <span className="muted">–</span>}</td>
                  </tr>
                ));
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

const REQ_LEVEL = { ok: 'ok', fail: 'error', unknown: 'info', 'n/a': 'info' } as const;

function ServiceRow({ p }: { p: ServiceProbe }) {
  return (
    <tr>
      <td>{p.service === 'submission' ? 'Submission' : 'IMAP'}</td>
      <td className="mono">
        {p.host}:{p.port}
        <div className="muted">{p.tlsMode === 'implicit' ? 'implicit TLS' : 'STARTTLS'}</div>
      </td>
      <td className="mono" style={{ maxWidth: 260, overflowWrap: 'anywhere' }}>
        {p.banner ?? <span className="muted">{p.error ?? '–'}</span>}
        {p.authBeforeTls.length > 0 && <div className="muted">AUTH before TLS: {p.authBeforeTls.join(', ')}</div>}
      </td>
      <td className="mono">{p.tls?.protocol ?? <span className="muted">–</span>}</td>
      <td>{p.tls?.chain[0] ? <Cert c={p.tls.chain[0]} /> : <span className="muted">–</span>}</td>
      <td>
        {p.tls ? (
          <Yes ok={p.tls.authorized && p.tls.hostnameMatch} yes="valid" no="invalid" />
        ) : (
          <span className="muted">–</span>
        )}
      </td>
    </tr>
  );
}

export function SendersDetails({ data }: DetailsProps) {
  const d = data as SendersData;
  return (
    <>
      <div className="subhead">Gmail / Yahoo sender requirements</div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Requirement</th>
              <th>For</th>
              <th>Status</th>
              <th>Seen</th>
            </tr>
          </thead>
          <tbody>
            {d.requirements.map((r) => (
              <tr key={r.id}>
                <td>{r.label}</td>
                <td className="small">{r.scope === 'all' ? 'all senders' : 'bulk senders'}</td>
                <td>
                  <StatusPill level={REQ_LEVEL[r.status]} text={r.status === 'fail' ? 'not met' : r.status} />
                </td>
                <td className="small" style={{ maxWidth: 420, overflowWrap: 'anywhere' }}>
                  {r.detail}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="subhead">
        Sending IPs {d.envelopeDomain && <span className="muted small">(SPF of {d.envelopeDomain})</span>}
      </div>
      {!d.ips.length ? (
        <div className="muted">None known: configure DOMAIN_n_SENDER_IPS or delivery tests.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>Seen via</th>
                <th>Reverse DNS</th>
                <th>Forward-confirmed</th>
                <th>SPF</th>
              </tr>
            </thead>
            <tbody>
              {d.ips.map((s) => (
                <tr key={s.ip}>
                  <td className="mono">{s.ip}</td>
                  <td className="small">{s.sources.join(', ')}</td>
                  <td className="mono">{s.ptr ?? <span className="muted">none</span>}</td>
                  <td>
                    <Yes ok={s.fcrdns} />
                  </td>
                  <td title={s.spfDetail ?? undefined}>
                    {s.spf ? (
                      <StatusPill
                        level={
                          s.spf === 'pass' ? 'ok' : s.spf === 'fail' || s.spf === 'permerror' ? 'error' : 'warning'
                        }
                        text={s.spf}
                      />
                    ) : (
                      <span className="muted">–</span>
                    )}
                    {s.spfDetail && <div className="muted small">{s.spfDetail}</div>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="subhead">Submission and IMAP servers</div>
      {!d.services.length ? (
        <div className="muted">None configured (DOMAIN_n_SMTPHOST, DOMAIN_n_IMAPHOST).</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Service</th>
                <th>Server</th>
                <th>Greeting</th>
                <th>TLS</th>
                <th>Certificate</th>
                <th>Valid</th>
              </tr>
            </thead>
            <tbody>
              {d.services.map((p) => (
                <ServiceRow key={`${p.service}-${p.host}-${p.port}`} p={p} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="subhead">Client autoconfiguration</div>
      <dl className="kv">
        {d.srv.map((s) => (
          <span key={s.name} style={{ display: 'contents' }}>
            <dt className="mono">{s.name.split('.').slice(0, 2).join('.')}</dt>
            <dd className="mono">
              {s.found ? (
                s.target === '.' ? (
                  '. (service not offered)'
                ) : (
                  `${s.target}:${s.port}`
                )
              ) : (
                <span className="muted">none</span>
              )}
            </dd>
          </span>
        ))}
        {d.autoconfig && (
          <>
            <dt>autoconfig</dt>
            <dd>
              <span className="mono">{d.autoconfig.url}</span>{' '}
              <span className="muted">{d.autoconfig.error ?? `HTTP ${d.autoconfig.status}`}</span>
            </dd>
          </>
        )}
      </dl>
    </>
  );
}

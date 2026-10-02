import type { RecordChange } from '../../shared/types.ts';
import { CHECK_LABEL } from '../../shared/paths.ts';
import { dateTime } from '../format.ts';

/** Changes of published records, newest first, with the old and the new value. */
export function ChangeList({
  changes,
  showDomain = true,
  showCheck = true,
}: {
  changes: RecordChange[];
  showDomain?: boolean;
  showCheck?: boolean;
}) {
  if (!changes.length) return <div className="muted">No changes recorded.</div>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>When</th>
            {showDomain && <th>Domain</th>}
            {showCheck && <th>Record</th>}
            <th>Change</th>
          </tr>
        </thead>
        <tbody>
          {changes.map((c) => (
            <tr key={c.id}>
              <td style={{ whiteSpace: 'nowrap' }}>{dateTime(c.at)}</td>
              {showDomain && <td>{c.domain}</td>}
              {showCheck && <td>{CHECK_LABEL[c.check]}</td>}
              <td>
                <div className="diff">
                  <span className="minus" aria-label="before">
                    −
                  </span>
                  <pre>{c.before ?? '(none)'}</pre>
                  <span className="plus" aria-label="after">
                    +
                  </span>
                  <pre>{c.after ?? '(none)'}</pre>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

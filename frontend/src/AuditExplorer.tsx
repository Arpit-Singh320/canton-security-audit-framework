import React, { useState, useMemo } from 'react';

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";

export interface AuditFinding {
  id: string;
  title: string;
  description: string;
  recommendation: string;
  severity: Severity;
  location: {
    file: string;
    line: number;
  };
  ruleId: string;
}

const severityColors: Record<Severity, { bg: string; text: string; border: string }> = {
  Critical:    { bg: '#5f0d11', text: '#ffccd0', border: '#a21d23' },
  High:        { bg: '#613200', text: '#ffd3a1', border: '#a65600' },
  Medium:      { bg: '#605400', text: '#fff3a8', border: '#a59300' },
  Low:         { bg: '#1e488f', text: '#d2e5ff', border: '#3b82f6' },
  Informational: { bg: '#30343a', text: '#c8cdd4', border: '#535b67' },
};

const allSeverities: Severity[] = ["Critical", "High", "Medium", "Low", "Informational"];

const SeverityBadge: React.FC<{ severity: Severity }> = ({ severity }) => {
  const colors = severityColors[severity];
  return (
    <span style={{
      backgroundColor: colors.bg,
      color: colors.text,
      border: `1px solid ${colors.border}`,
      padding: '2px 8px',
      borderRadius: '12px',
      fontSize: '0.75rem',
      fontWeight: '500',
      textTransform: 'uppercase',
      letterSpacing: '0.5px'
    }}>
      {severity}
    </span>
  );
};

const FindingCard: React.FC<{ finding: AuditFinding }> = ({ finding }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div style={{
      backgroundColor: '#1c1c1e',
      border: '1px solid #3a3a3c',
      borderRadius: '8px',
      marginBottom: '1rem',
      padding: '1rem',
      color: '#e5e5e7',
      fontFamily: 'sans-serif',
    }}>
      <div
        onClick={() => setIsExpanded(!isExpanded)}
        style={{ cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
      >
        <div>
          <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1.1rem', color: '#f5f5f7' }}>{finding.title}</h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <SeverityBadge severity={finding.severity} />
            <code style={{ fontSize: '0.8rem', color: '#9a9a9f' }}>
              {finding.location.file}:{finding.location.line}
            </code>
          </div>
        </div>
        <span style={{ fontSize: '1.5rem', transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }}>
          ›
        </span>
      </div>
      {isExpanded && (
        <div style={{ marginTop: '1rem', borderTop: '1px solid #3a3a3c', paddingTop: '1rem' }}>
          <h4 style={{ margin: '0 0 0.5rem 0', color: '#c8cdd4' }}>Description</h4>
          <p style={{ margin: '0 0 1rem 0', whiteSpace: 'pre-wrap', color: '#b0b0b8', lineHeight: '1.5' }}>{finding.description}</p>
          <h4 style={{ margin: '0 0 0.5rem 0', color: '#c8cdd4' }}>Recommendation</h4>
          <p style={{ margin: '0 0 1rem 0', whiteSpace: 'pre-wrap', color: '#b0b0b8', lineHeight: '1.5' }}>{finding.recommendation}</p>
          <div style={{ fontSize: '0.8rem', color: '#9a9a9f' }}>
            Rule ID: <code style={{ backgroundColor: '#2c2c2e', padding: '2px 4px', borderRadius: '4px' }}>{finding.ruleId}</code>
          </div>
        </div>
      )}
    </div>
  );
};

interface AuditExplorerProps {
  findings: AuditFinding[];
}

export const AuditExplorer: React.FC<AuditExplorerProps> = ({ findings }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverities, setSelectedSeverities] = useState<Set<Severity>>(new Set(allSeverities));

  const handleSeverityToggle = (severity: Severity) => {
    setSelectedSeverities(prev => {
      const newSet = new Set(prev);
      if (newSet.has(severity)) {
        newSet.delete(severity);
      } else {
        newSet.add(severity);
      }
      return newSet;
    });
  };

  const filteredFindings = useMemo(() => {
    const lowerCaseQuery = searchQuery.toLowerCase();
    return findings.filter(finding => {
      const severityMatch = selectedSeverities.has(finding.severity);
      if (!severityMatch) return false;

      const queryMatch =
        finding.title.toLowerCase().includes(lowerCaseQuery) ||
        finding.description.toLowerCase().includes(lowerCaseQuery) ||
        finding.ruleId.toLowerCase().includes(lowerCaseQuery) ||
        finding.location.file.toLowerCase().includes(lowerCaseQuery);

      return queryMatch;
    });
  }, [findings, searchQuery, selectedSeverities]);

  return (
    <div style={{
      maxWidth: '900px',
      margin: '0 auto',
      padding: '2rem',
      backgroundColor: '#121212',
      color: '#e5e5e7',
      fontFamily: 'system-ui, -apple-system, sans-serif'
    }}>
      <h1 style={{ borderBottom: '1px solid #3a3a3c', paddingBottom: '1rem' }}>Security Audit Findings</h1>

      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Search findings..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          style={{
            flexGrow: 1,
            padding: '0.75rem',
            backgroundColor: '#1c1c1e',
            border: '1px solid #3a3a3c',
            borderRadius: '6px',
            color: '#e5e5e7',
            fontSize: '1rem',
            outline: 'none',
          }}
        />
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          {allSeverities.map(severity => (
            <button
              key={severity}
              onClick={() => handleSeverityToggle(severity)}
              style={{
                padding: '0.5rem 1rem',
                border: `1px solid ${selectedSeverities.has(severity) ? severityColors[severity].border : '#3a3a3c'}`,
                borderRadius: '6px',
                backgroundColor: selectedSeverities.has(severity) ? severityColors[severity].bg : 'transparent',
                color: selectedSeverities.has(severity) ? severityColors[severity].text : '#9a9a9f',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              {severity}
            </button>
          ))}
        </div>
      </div>

      <div style={{ marginBottom: '1.5rem', color: '#9a9a9f' }}>
        Showing {filteredFindings.length} of {findings.length} findings
      </div>

      <div>
        {filteredFindings.length > 0 ? (
          filteredFindings.map(finding => <FindingCard key={finding.id} finding={finding} />)
        ) : (
          <div style={{
            textAlign: 'center',
            padding: '3rem',
            border: '1px dashed #3a3a3c',
            borderRadius: '8px',
            color: '#9a9a9f'
          }}>
            <p>No findings match your current filters.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AuditExplorer;
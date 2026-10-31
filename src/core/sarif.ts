import { BLA_IDENTITY } from "../identity.js";
import type { AuditReport } from "./types.js";
import type { ReleaseExposureReport } from "./release-exposure.js";

export interface SarifLog {
  readonly $schema: string;
  readonly version: "2.1.0";
  readonly runs: readonly [
    {
      readonly tool: {
        readonly driver: {
          readonly name: string;
          readonly fullName: string;
          readonly version: string;
          readonly informationUri: string;
          readonly rules: readonly {
            readonly id: string;
            readonly name: string;
            readonly shortDescription: { readonly text: string };
            readonly defaultConfiguration: {
              readonly level: "error" | "warning" | "note";
            };
          }[];
        };
      };
      readonly results: readonly {
        readonly ruleId: string;
        readonly level: "error" | "warning" | "note";
        readonly message: { readonly text: string };
        readonly locations: readonly [
          {
            readonly physicalLocation: {
              readonly artifactLocation: { readonly uri: string };
              readonly region?: { readonly startLine: number };
            };
          },
        ];
      }[];
    },
  ];
}

/**
 * Formats an `AuditReport` (and optional `ReleaseExposureReport`) as a SARIF 2.1.0 JSON document
 * compatible with GitHub Code Scanning (`github/codeql-action/upload-sarif`).
 */
export function buildSarifReport(
  audit: AuditReport,
  releaseExposure?: ReleaseExposureReport | null,
): SarifLog {
  const rulesMap = new Map<
    string,
    {
      id: string;
      name: string;
      shortDescription: { text: string };
      defaultConfiguration: { level: "error" | "warning" | "note" };
    }
  >();

  const results: SarifLog["runs"][0]["results"][number][] = [];

  for (const item of audit.exposedItems) {
    const ruleId = `BLA-AUDIT-${item.kind.toUpperCase()}`;
    const level: "error" | "warning" | "note" =
      item.riskLevel === "critical"
        ? "error"
        : item.riskLevel === "high"
          ? "warning"
          : "note";

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: `ExposedArtifact_${item.kind}`,
        shortDescription: {
          text: `Artifact surface (${item.kind}) exposed to automated reverse-engineering tool (${item.reaToolUsed})`,
        },
        defaultConfiguration: { level },
      });
    }

    const lineMatch = /:(\d+)$/.exec(item.location);
    const uriPart = lineMatch
      ? item.location.slice(0, lineMatch.index)
      : item.location;
    const startLine = lineMatch ? Number.parseInt(lineMatch[1]!, 10) : undefined;
    const normalizedUri = (uriPart || audit.targetPath).replace(/\\/g, "/");

    results.push({
      ruleId,
      level,
      message: {
        text: `${item.name}: ${item.reason} (Est. reconstruction: ${item.estimatedTokensToReconstruct} tokens / $${item.estimatedCostUsd.toFixed(2)})`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: normalizedUri },
            ...(startLine && Number.isFinite(startLine) ? { region: { startLine } } : {}),
          },
        },
      ],
    });
  }

  if (releaseExposure) {
    for (const f of releaseExposure.findings) {
      const ruleId = `BLA-RELEASE-${f.kind.toUpperCase()}`;
      const level: "error" | "warning" | "note" =
        f.kind === "embedded-source-text" ? "error" : "warning";
      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: `ReleaseExposure_${f.kind}`,
          shortDescription: { text: `Release source-map exposure (${f.kind}, ${f.representation})` },
          defaultConfiguration: { level },
        });
      }
      results.push({
        ruleId,
        level,
        message: {
          text: `${f.kind} (${f.representation}) in ${f.file} — Run "npx bla-agents defend" to replace with decoy source maps.`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: f.file.replace(/\\/g, "/") },
            },
          },
        ],
      });
    }
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: BLA_IDENTITY.packageName,
            fullName: BLA_IDENTITY.fullName,
            version: BLA_IDENTITY.version,
            informationUri: "https://bla.tools",
            rules: [...rulesMap.values()],
          },
        },
        results,
      },
    ],
  };
}

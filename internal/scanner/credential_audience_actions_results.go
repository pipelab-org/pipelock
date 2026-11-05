// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/destination"
)

// githubActionsResultsHosts are the exact results storage accounts published by
// GET https://api.github.com/meta in domains.actions, fetched 2026-11-05:
// productionresultssa0..19, productionresultssa30..49, and
// productionresultssa100..199, each under .blob.core.windows.net. The literal
// list below records that snapshot; unpublished numbers stay blocked.
// *.blob.core.windows.net is not an audience: any Azure customer can create
// an account on that suffix.
var githubActionsResultsHosts = []string{
	"productionresultssa0.blob.core.windows.net",
	"productionresultssa1.blob.core.windows.net",
	"productionresultssa2.blob.core.windows.net",
	"productionresultssa3.blob.core.windows.net",
	"productionresultssa4.blob.core.windows.net",
	"productionresultssa5.blob.core.windows.net",
	"productionresultssa6.blob.core.windows.net",
	"productionresultssa7.blob.core.windows.net",
	"productionresultssa8.blob.core.windows.net",
	"productionresultssa9.blob.core.windows.net",
	"productionresultssa10.blob.core.windows.net",
	"productionresultssa11.blob.core.windows.net",
	"productionresultssa12.blob.core.windows.net",
	"productionresultssa13.blob.core.windows.net",
	"productionresultssa14.blob.core.windows.net",
	"productionresultssa15.blob.core.windows.net",
	"productionresultssa16.blob.core.windows.net",
	"productionresultssa17.blob.core.windows.net",
	"productionresultssa18.blob.core.windows.net",
	"productionresultssa19.blob.core.windows.net",
	"productionresultssa30.blob.core.windows.net",
	"productionresultssa31.blob.core.windows.net",
	"productionresultssa32.blob.core.windows.net",
	"productionresultssa33.blob.core.windows.net",
	"productionresultssa34.blob.core.windows.net",
	"productionresultssa35.blob.core.windows.net",
	"productionresultssa36.blob.core.windows.net",
	"productionresultssa37.blob.core.windows.net",
	"productionresultssa38.blob.core.windows.net",
	"productionresultssa39.blob.core.windows.net",
	"productionresultssa40.blob.core.windows.net",
	"productionresultssa41.blob.core.windows.net",
	"productionresultssa42.blob.core.windows.net",
	"productionresultssa43.blob.core.windows.net",
	"productionresultssa44.blob.core.windows.net",
	"productionresultssa45.blob.core.windows.net",
	"productionresultssa46.blob.core.windows.net",
	"productionresultssa47.blob.core.windows.net",
	"productionresultssa48.blob.core.windows.net",
	"productionresultssa49.blob.core.windows.net",
	"productionresultssa100.blob.core.windows.net",
	"productionresultssa101.blob.core.windows.net",
	"productionresultssa102.blob.core.windows.net",
	"productionresultssa103.blob.core.windows.net",
	"productionresultssa104.blob.core.windows.net",
	"productionresultssa105.blob.core.windows.net",
	"productionresultssa106.blob.core.windows.net",
	"productionresultssa107.blob.core.windows.net",
	"productionresultssa108.blob.core.windows.net",
	"productionresultssa109.blob.core.windows.net",
	"productionresultssa110.blob.core.windows.net",
	"productionresultssa111.blob.core.windows.net",
	"productionresultssa112.blob.core.windows.net",
	"productionresultssa113.blob.core.windows.net",
	"productionresultssa114.blob.core.windows.net",
	"productionresultssa115.blob.core.windows.net",
	"productionresultssa116.blob.core.windows.net",
	"productionresultssa117.blob.core.windows.net",
	"productionresultssa118.blob.core.windows.net",
	"productionresultssa119.blob.core.windows.net",
	"productionresultssa120.blob.core.windows.net",
	"productionresultssa121.blob.core.windows.net",
	"productionresultssa122.blob.core.windows.net",
	"productionresultssa123.blob.core.windows.net",
	"productionresultssa124.blob.core.windows.net",
	"productionresultssa125.blob.core.windows.net",
	"productionresultssa126.blob.core.windows.net",
	"productionresultssa127.blob.core.windows.net",
	"productionresultssa128.blob.core.windows.net",
	"productionresultssa129.blob.core.windows.net",
	"productionresultssa130.blob.core.windows.net",
	"productionresultssa131.blob.core.windows.net",
	"productionresultssa132.blob.core.windows.net",
	"productionresultssa133.blob.core.windows.net",
	"productionresultssa134.blob.core.windows.net",
	"productionresultssa135.blob.core.windows.net",
	"productionresultssa136.blob.core.windows.net",
	"productionresultssa137.blob.core.windows.net",
	"productionresultssa138.blob.core.windows.net",
	"productionresultssa139.blob.core.windows.net",
	"productionresultssa140.blob.core.windows.net",
	"productionresultssa141.blob.core.windows.net",
	"productionresultssa142.blob.core.windows.net",
	"productionresultssa143.blob.core.windows.net",
	"productionresultssa144.blob.core.windows.net",
	"productionresultssa145.blob.core.windows.net",
	"productionresultssa146.blob.core.windows.net",
	"productionresultssa147.blob.core.windows.net",
	"productionresultssa148.blob.core.windows.net",
	"productionresultssa149.blob.core.windows.net",
	"productionresultssa150.blob.core.windows.net",
	"productionresultssa151.blob.core.windows.net",
	"productionresultssa152.blob.core.windows.net",
	"productionresultssa153.blob.core.windows.net",
	"productionresultssa154.blob.core.windows.net",
	"productionresultssa155.blob.core.windows.net",
	"productionresultssa156.blob.core.windows.net",
	"productionresultssa157.blob.core.windows.net",
	"productionresultssa158.blob.core.windows.net",
	"productionresultssa159.blob.core.windows.net",
	"productionresultssa160.blob.core.windows.net",
	"productionresultssa161.blob.core.windows.net",
	"productionresultssa162.blob.core.windows.net",
	"productionresultssa163.blob.core.windows.net",
	"productionresultssa164.blob.core.windows.net",
	"productionresultssa165.blob.core.windows.net",
	"productionresultssa166.blob.core.windows.net",
	"productionresultssa167.blob.core.windows.net",
	"productionresultssa168.blob.core.windows.net",
	"productionresultssa169.blob.core.windows.net",
	"productionresultssa170.blob.core.windows.net",
	"productionresultssa171.blob.core.windows.net",
	"productionresultssa172.blob.core.windows.net",
	"productionresultssa173.blob.core.windows.net",
	"productionresultssa174.blob.core.windows.net",
	"productionresultssa175.blob.core.windows.net",
	"productionresultssa176.blob.core.windows.net",
	"productionresultssa177.blob.core.windows.net",
	"productionresultssa178.blob.core.windows.net",
	"productionresultssa179.blob.core.windows.net",
	"productionresultssa180.blob.core.windows.net",
	"productionresultssa181.blob.core.windows.net",
	"productionresultssa182.blob.core.windows.net",
	"productionresultssa183.blob.core.windows.net",
	"productionresultssa184.blob.core.windows.net",
	"productionresultssa185.blob.core.windows.net",
	"productionresultssa186.blob.core.windows.net",
	"productionresultssa187.blob.core.windows.net",
	"productionresultssa188.blob.core.windows.net",
	"productionresultssa189.blob.core.windows.net",
	"productionresultssa190.blob.core.windows.net",
	"productionresultssa191.blob.core.windows.net",
	"productionresultssa192.blob.core.windows.net",
	"productionresultssa193.blob.core.windows.net",
	"productionresultssa194.blob.core.windows.net",
	"productionresultssa195.blob.core.windows.net",
	"productionresultssa196.blob.core.windows.net",
	"productionresultssa197.blob.core.windows.net",
	"productionresultssa198.blob.core.windows.net",
	"productionresultssa199.blob.core.windows.net",
}

// actionsResultsSASMaxLifetime keeps the attestation bundle cap these grants
// already used. GitHub's REST docs describe the job-log, run-log and artifact
// download links as valid for one minute, but the SAS GitHub actually signs runs
// from 5 seconds before issue to 10 minutes after: 605 seconds on every job-log
// and artifact redirect sampled 2026-11-05 from productionresultssa17 and
// productionresultssa32. A one-minute cap would refuse every live download.
// Narrowing the cap to the issued window is a separate decision.
// https://docs.github.com/en/rest/actions/workflow-jobs#download-job-logs-for-a-workflow-run
// https://docs.github.com/en/rest/actions/artifacts#download-an-artifact
const actionsResultsSASMaxLifetime = attestationBundleSASMaxLifetime

const actionsResultsGUID = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

// actionsResultsPathPattern is the blob path GitHub issues for a job log
// (.../logs/job/job-logs.txt) and a workflow artifact
// (.../artifacts/<sha256>.zip), both observed from live redirects on
// 2026-10-06. The container and run segments are fixed and the rest is a clean
// path of plain file-name characters, so an encoded slash, a traversal segment
// or a free-form value cannot ride the allowance.
var actionsResultsPathPattern = regexp.MustCompile(
	`^/actions-results/` + actionsResultsGUID + `/workflow-job-run-` + actionsResultsGUID +
		`/(?:logs|artifacts)/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)

// actionsResultsOverrideFormats pins the two response-header overrides an
// Actions artifact redirect carries (rscd and rsct) to the shape observed on
// 2026-10-06: `attachment; filename="<artifact name>"` with the name in quotes,
// and a plain media type. An artifact name is chosen by the workflow author,
// so it can score above the entropy threshold; the pin admits only letters,
// digits, space and `.`, `_`, `+`, `-`, up to 255 bytes, and it applies only on
// a valid results SAS at one of the published accounts.
var actionsResultsOverrideFormats = map[string]*regexp.Regexp{
	"rscd": regexp.MustCompile(`^attachment; filename="[A-Za-z0-9._+ -]{1,` + strconv.Itoa(releaseGrantResponseOverrideMaxFilename) + `}"$`),
	"rsct": regexp.MustCompile(`^[a-z]{1,32}/[a-z0-9][a-z0-9.+-]{0,63}$`),
}

func actionsResultsPath(u *url.URL) bool {
	p := u.EscapedPath()
	if p == "" || strings.Contains(p, "%") || path.Clean(p) != p {
		return false
	}
	return actionsResultsPathPattern.MatchString(p)
}

// actionsResultsSASAllowed grants the Azure SAS in a GitHub Actions results
// redirect. It is the attestation bundle predicate on a different set of
// accounts and paths: exact published account, https, a results blob path, and
// the same read-only blob user-delegation SAS with every signed field once in
// its documented format, start time included, inside the Actions lifetime
// cap. There is no co-located JWT. The proxy cannot verify the HMAC, so the
// bound is the destination: the value this allow releases is the signature
// itself, and it can only reach GitHub's own storage account. Every other
// credential in the URL is still scanned.
func actionsResultsSASAllowed(host, target string, now time.Time) bool {
	if !destination.MatchesDomainList(host, githubActionsResultsHosts) {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	return actionsResultsPath(parsed) && actionsResultsSASQueryValid(parsed, now)
}

// actionsResultsSASQueryValid reuses the signed-field and read-only blob rules
// of attestation bundles, with the Actions lifetime cap.
func actionsResultsSASQueryValid(parsed *url.URL, now time.Time) bool {
	return githubBlobSASQueryValid(parsed, now, actionsResultsSASMaxLifetime)
}

// githubBlobSASAllowed is the one predicate for a SAS GitHub itself issues on
// its own storage accounts without a release grant: the attestation bundle
// accounts and the Actions results accounts. The DLP candidate decision, the
// url_query surface decision and the query-entropy exemption all answer
// through it, so none can decide a different SAS than the others.
func githubBlobSASAllowed(host, target string, now time.Time) bool {
	return attestationBundleSASAllowed(host, target, now) || actionsResultsSASAllowed(host, target, now)
}

# Frontend campaign integration contract

Campaign execution controls should remain disabled until the UI implements every
per-host approval step below.

1. Create a draft with `POST /campaigns` and selected `hostIds`.
2. Create proposals with `POST /campaigns/{campaignId}/proposals`.
3. Render every item in `campaign.hosts`, including its `state`,
   `planVersion`, `planHash`, and `failureSummary`.
4. Approve each patch plan separately with
   `POST /campaigns/{campaignId}/hosts/{hostId}/approve`. Send the displayed
   plan version, plan hash, and the exact typed hostname.
5. When the host state is `awaiting_reboot_approval`, request a second exact
   hostname confirmation and call
   `POST /campaigns/{campaignId}/hosts/{hostId}/reboot-approval`.
6. Never offer a campaign-wide approval action. Rejection is also per host at
   `POST /campaigns/{campaignId}/hosts/{hostId}/reject`.
7. Enable `POST /campaigns/{campaignId}/execute` only when at least one host is
   `approved`. The API queues only approved hosts and leaves every other host
   unchanged.
8. Use `POST /campaigns/{campaignId}/cancel` to cancel queued or scheduled work.

When a host is `plan_changed`, disable approval for that entry. Calling the
proposals endpoint again creates a fresh proposal for changed hosts without
carrying either approval forward.

Campaign states are `draft`, `proposing`, `awaiting_approval`, `ready`,
`running`, `partially_succeeded`, `succeeded`, `failed`, `cancelling`, and
`canceled`. Host states provide the authoritative detail for mixed approval and
mixed execution outcomes.

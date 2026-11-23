package prcode

import "github.com/sisaku-security/sisakulint/actions/job"

// approval is what approves the run of s (actions/job).
func (s *CheckoutSite) approval() { s.Approval, s.Environment = job.ApprovalOf(s.PRCodeOn, s.Job) }

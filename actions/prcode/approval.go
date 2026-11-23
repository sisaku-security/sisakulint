package prcode

import "github.com/gh-intel/sisakulint/actions/job"

// approval is what approves the run of s (actions/job).
func (s *CheckoutSite) approval() { s.Approval, s.Environment = job.ApprovalOf(s.PRCodeOn, s.Job) }

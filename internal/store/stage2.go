package store

// Stage 2's query surface.
//
// The four surfaces a shell needs beyond a page render — the file tree, the tag
// pages, the related list and the campaign status rollups — are the first
// queries in this package that are asked a question about a *page* rather than
// about a secret. They are collected here, and every one of them takes the
// principal it is answering and applies authz.SecretVisibleSQL verbatim where a
// tag or a heading could have been written inside a secret. That is the reason
// they sit in one file: the shapes are the contract, and a sixth rollup added
// later has four neighbours to copy rather than none.
//
// The functions are implemented in tree.go and campaign.go. Their signatures,
// which httpapi's handlers are written against, are:
//
//	func ListAllPages(ctx, q Queryer, p authz.Principal) ([]Page, error)
//	func ListTaggedPages(ctx, q Queryer, p authz.Principal, tag string) ([]Page, error)
//	func CountTaggedPages(ctx, q Queryer, p authz.Principal, tag string) (int, error)
//	func CountOpenThreads(ctx, q Queryer, p authz.Principal) (int, error)
//	func ListOpenThreads(ctx, q Queryer, p authz.Principal, limit int) ([]Page, error)
//	func ListRecentPagesExcluding(ctx, q Queryer, p authz.Principal, excludeID int64, limit int) ([]Page, error)
//	func ListParty(ctx, q Queryer, p authz.Principal, limit int) ([]PartyMember, error)
//	func ListRelatedPages(ctx, q Queryer, p authz.Principal, pageID int64, limit int) ([]Page, error)
//	func ListCommandPages(ctx, q Queryer, p authz.Principal, prefix string, limit int) ([]Page, error)
//
// The four rules that are not visible in those signatures:
//
//  1. A principal is a parameter on all nine even where v1 filters nothing.
//     A page is not hidden in v1, but a list-of-titles query that cannot filter
//     is a query whose filtering will be added somewhere else, later, by
//     someone in a hurry.
//  2. Where a tag could have come from a secret, the join carries
//     authz.SecretVisibleSQL. A page whose only occurrence of a tag is inside a
//     secret the viewer cannot read contributes zero to both the list and the
//     count, and the count is never len() of a windowed list.
//  3. A count and its list come from the same predicate, always. A panel whose
//     badge says three and whose list shows one is an existence leak.
//  4. The COUNT and the SELECT use the identical WHERE clause, assembled from
//     one constant, for the reason AGENTS.md §2.4 gives: two predicates that
//     look alike are two predicates that will diverge.

const (
	// TagSession marks a session log. The current session is the one with the
	// highest `date:` frontmatter.
	TagSession = "session"
	// TagOpenThread marks a thread that is still running. A thread is closed by
	// removing the tag, so this tag is the closure queue and nothing else is.
	TagOpenThread = "open-thread"
	// TypeCharacter is the page type the party list reads. It is a frontmatter
	// `type:`, not a tag, and it is the one page type v1 recognises without a
	// plugin being installed.
	TypeCharacter = "character"
)

// PartyMember is one character sheet and the player who owns it.
type PartyMember struct {
	// Page is the character sheet.
	Page Page
	// OwnerDisplayName is the owning account's display name, never its username.
	//
	// The username is an account identifier as well as a display string, and a
	// sidebar that prints it next to a character sheet hands out the identifier
	// for every player in the campaign to every reader of the campaign.
	OwnerDisplayName string
}

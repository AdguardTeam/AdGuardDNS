package websvc

// ServerGroup is a semantic alias for names of server groups.
type ServerGroup = string

// Valid server groups.
const (
	ServerGroupAdultBlockingPage   ServerGroup = "adult_blocking_page"
	ServerGroupGeneralBlockingPage ServerGroup = "general_blocking_page"
	ServerGroupLinkedIP            ServerGroup = "linked_ip"
	ServerGroupNonDoH              ServerGroup = "non_doh"
	ServerGroupSafeBrowsingPage    ServerGroup = "safe_browsing_page"
)

// loggerKeyGroup is the key used by server groups
const loggerKeyGroup = "group"

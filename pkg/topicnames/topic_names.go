package topicnames

// https://stackoverflow.com/questions/43726571/what-is-the-best-practice-for-naming-kafka-topics
// Avoid topic names based on things that change
// Avoid topic names based on information that would be stored in other places
// Avoid topic names based on their planned consumers/producers. This is essentially a special case of the first advice :D.
// Decide casing early on, and consider enforcing it or at least check/monitor it. This way you catch offenders early on.

// <message type>.<dataset name>.<data name>
// logging
// For logging data (slf4j, syslog, etc)

// queuing
// For classical queuing use cases.

// tracking
// For tracking events such as user clicks, page views, ad views, etc.

// etl/db
// For ETL and CDC use cases such as database feeds.

// streaming
// For intermediate topics created by stream processing pipelines.

// push
// For data that’s being pushed from offline (batch computation) environments into online environments.

// user
// For user-specific data such as scratch and test topics.

// message-type.namespace.verb.resource.version

const (
	// QueuingVCSaveDocumentV0 is the name of the topic for saving VC data
	QueuingVCSaveDocumentV0 = "queuing.vc.save.document.v0"

	// QueuingVCDeleteDocumentV0 is the name of the topic for deleting VC data
	QueuingVCDeleteDocumentV0 = "queuing.vc.delete.document.v0"
)

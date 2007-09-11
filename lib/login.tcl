#this is an include and requires a return_url parameter

set authenticated_p [ad_get_client_property auth-cas authenticated_p]

#if user was not authenticated redirect to cas-web module as defined in the parameters
if {[empty_string_p $authenticated_p] || $authenticated_p != 1} {
	#lets load the required parameters
	auth::cas::authentication::GetParameters
	ns_log Debug "auth-cas: Redirecting to $cas(server)login?service=[ns_conn location]$cas(handler)"
	ad_returnredirect "$cas(server)login?service=[ns_conn location]$cas(handler)"
    }
} else {
    ad_returnredirect $return_url
}

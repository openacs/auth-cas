ad_library {
    Procs for cas authentication

    @author Nima Mazloumi nima.mazloumi@gmx.de)
    @creation-date 2007-06-29
}

namespace eval auth {}
namespace eval auth::cas {}
namespace eval auth::cas::authentication {}

ad_proc -private auth::cas::after_install {} {} {
    set spec {
        contract_name "auth_authentication"
        owner "auth-cas"
        name "CAS"
        pretty_name "CAS"
        aliases {
            Authenticate auth::cas::authentication::Authenticate
            GetParameters auth::cas::authentication::GetParameters
            MergeUser auth::cas::authentication::MergeUser
        }
    }

    set auth_impl_id [acs_sc::impl::new_from_spec -spec $spec]
}

ad_proc -private auth::cas::before_uninstall {} {} {
    acs_sc::impl::delete -contract_name "auth_authentication" -impl_name "CAS"
}

#####
#
# CAS Authentication Driver
#
#####

ad_proc -private auth::cas::authentication::Authenticate {
    username
    password
    {parameters {}}
    {authority_id {}}
} {
    Implements the Authenticate operation of the auth_authentication service contract for CAS. 
    This proc is only called if the oacs login page was used.
    We simply redirect to CAS here
} {
    ad_returnredirect "[lindex $parameters 0]/login?service=[ns_conn location][lindex $parameters 5]"
}

ad_proc -private auth::cas::authentication::GetParameters {} {
    Implements the GetParameters operation of the auth_authentication 
    service contract for CAS. Returns a list as well as upvars an array called cas
} {
    # we upvar the parameters as well for named access to the parameters
    upvar cas _cas

    set server [parameter::get_from_package_key -parameter CasServer -package_key "auth-cas"]
    regexp -nocase {^(http.?://)?([^:/]+)(:([0-9]+))?(/.*)} $server tX_x tX_protocol tX_server tX_y tX_port tX_path

    set _cas(host) $tX_server
    set _cas(path) $tX_path
    set _cas(port) $tX_port
    set _cas(protocol) $tX_protocol
    set _cas(handler) [parameter::get_from_package_key -parameter LocalSsoHandler -package_key "auth-cas"]

    #in some cases not this OpenACS instance but a third service shall be used for ticket validation use that if provided or default to the oacs instance
    set _cas(type) [parameter::get_from_package_key -parameter ValidationType -package_key "auth-cas"]
    set _cas(server) $server

    #proc must return a list as well in for the service contract auth::cas::authentication::Authenticate to work correctly
    return [list $_cas(server) $_cas(host) $_cas(path) $_cas(port) $_cas(protocol) $_cas(handler) $_cas(type)]
}

ad_proc -private auth::cas::authentication::MergeUser {
    from_user_id
    to_user_id
    {authority_id ""}
} {
    Required but not used MergeUser operation for auth_authentication service contract
} {
    #do nothing
}

ad_proc -private auth::cas::authentication::validate {
    -ticket
    {-service ""}
    {-return_url ""}
} {
    Validates a ticket or tries to get a new ticket from CAS server. Supported are http/https as well as CAS 1.0 and 2.0 validation.
} {
    auth::cas::authentication::GetParameters

    if {[empty_string_p $return_url]} {
	set return_url [parameter::get_from_package_key -package_key acs-kernel -parameter IndexRedirectUrl]
    }

    #if no external service is given we use the default
    if {[empty_string_p $service]} {
	set service "[ns_conn location]$cas(handler)"
    }
    
    #if no ticket passed get a ticket
    if {[empty_string_p $ticket]} {

	ns_log Debug "auth-cas: No ticket, redirecting to $cas(server)login?service=$service"
	ad_returnredirect "$cas(server)login?service=$service"

    } else {

	#CAS validation version
	switch $cas(type) {
	    1.0 {
		set validatePath validate
	    }
	    2.0 {
		set validatePath serviceValidate
	    }
	}

	set url "$cas(server)$validatePath?ticket=$ticket&service=$service"

	#get cas response for the given ticket
	switch $cas(protocol) {
	    http:// {
		set response [ns_httpget $url]
	    }
	    https:// {
                #alternatively we can use nsopenssl module if available
                #set response [ns_httpsget $url]
                package require http
                package require tls
                http::register https 443 [list ::tls::socket]
                set handle [http::geturl $url]
                set response [::http::data $handle]
	    }
	}

	ns_log Debug "auth-cas: $url\n$response"

	set message ""
	set validation_failed_p 1
	
	#parse response depending on the cas validation version
        switch $cas(type) {
	    1.0 {
		#validation failed
		if {[lindex $response 0] == "no"} {
		    set validation_failed_p 1
		    set message "<b><small><center><font color=\"red\">Validation failed for ticket $ticket</font></center></small></b>"
		}
		
		#validation succeeded, check if user exists and create cookie
		if {[lindex $response 0] == "yes"} {
		    set username [lindex $response 1]
		    set validation_failed_p 0
		}
	    }
	    2.0 {
		set query "//cas:serviceResponse/cas:authenticationSuccess/cas:user/text()"
		dom parse $response document
		$document documentElement root
		set textNode [$root selectNodes $query]
		if {![empty_string_p $textNode]} {
		    #validation succeeded, check if user exists and create cookie
		    set username [$textNode nodeValue]
		    set validation_failed_p 0
		} else {
		    #validation failed, return error message
		    set validation_failed_p 1
		    set query "//cas:serviceResponse/cas:authenticationFailure"
		    dom parse $response document
		    $document documentElement root
		    set failureNode [$root selectNodes $query]
		    set errorCode [$failureNode getAttribute code]
		    set textNode [$failureNode selectNodes text()]
		    set reason [$textNode nodeValue]
		    set message "<b><small><center><font color=\"red\">$reason ($errorCode)</font></center></small></b>"
		}
	    }
	}

	if {$validation_failed_p} {
	    ad_set_client_property auth-cas authenticated_p 0
	    util_user_message -html -message $message
	} else {
	    set authority_id [db_string select_first_authority {select authority_id from auth_authorities order by sort_order limit 1} -default [auth::authority::local]]
	    set user_id [acs_user::get_by_username -authority_id $authority_id -username $username]
	    
	    # Issue login cookie if login was successful
	    auth::issue_login -user_id $user_id -account_status "ok"
	    ad_set_client_property auth-cas authenticated_p 1
	}

	ad_returnredirect $return_url
    }
}

# Service Page for CAS

ad_page_contract {    
    
    @author Nima Mazloumi (nima.mazloumi@gmx.de)
    @creation-date 2007-07-03
} {
    {ticket ""}
} -properties {
} -validate {
} -errors {
}

set authenticated_p [ad_get_client_property auth-cas authenticated_p]
set return_url [parameter::get_from_package_key -package_key acs-kernel -parameter IndexRedirectUrl]

#if invalid session
if {[empty_string_p $authenticated_p] || $authenticated_p != 1} {
    ns_log Debug "auth-cas: authenticated_p '$authenticated_p' validating ticket"
    auth::cas::authentication::validate -ticket $ticket -return_url $return_url
} else {
    ns_log Debug "auth-cas: authenticated_p '$authenticated_p' redirecting to $return_url"
    ad_returnredirect $return_url
}

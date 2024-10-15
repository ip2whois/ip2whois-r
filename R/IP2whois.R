#' @title Set IP2Location.io API key
#'
#' @description Set IP2Location.io API key for lookup. Free API key can be obtained from <https://www.ip2location.io/sign-up?ref=1/>
#' @param api_key IP2Location.io API key
#' @return NULL
#' @import reticulate
#' @export
#' @examples \dontrun{
#' set_api_key("YOUR_API_KEY")
#' }
#'

set_api_key <- function(api_key) {
  py_run_string("import ip2whois")
  apikeyString = paste("ip2whois_init = ip2whois.Api('", api_key , "')", sep = "")
  py_run_string(apikeyString)
}

#' @title Lookup for WHOIS information
#'
#' @description Lookup for a comprehensive of the WHOIS information
#' @param domain domain name to lookup for
#' @return Return the WHOIS information about the domain
#' @import reticulate
#' @import jsonlite
#' @export
#' @examples \dontrun{
#' lookup("example.com")
#' }
#'

lookup <- function(domain){
  py_run_string("import json")
  address = paste("rec = ip2whois_init.lookup('", domain, "')", sep = "")
  py_run_string(address)
  py_run_string("j = json.dumps(rec)")
  result = fromJSON(py$j)
  return(result)
}

#' @title Get Punycode for domain name
#'
#' @description Get Punycode for domain name.
#' @param domain domain name to get punycode for
#' @return Return the converted punycode of the domain
#' @import reticulate
#' @export
#' @examples \dontrun{
#' get_punycode("täst.de")
#' }
#'
get_punycode <- function(domain){
  get_punycode_string = paste("result = ip2whois_init.getPunycode('", domain, "')", sep = "")
  py_run_string(get_punycode_string)
  result_from_python <- py$result
  return(result_from_python)
}

#' @title Get Normat Text from a punycode
#'
#' @description Get Normat Text from a punycode for domain name.
#' @param domain The punycode domain name
#' @return Return normal domain name in text
#' @import reticulate
#' @export
#' @examples \dontrun{
#' get_normal_text("xn--tst-qla.de")
#' }
#'
get_normal_text <- function(domain){
  get_normal_text_string = paste("result = ip2whois_init.getNormalText('", domain, "')", sep = "")
  py_run_string(get_normal_text_string)
  result_from_python <- py$result
  return(result_from_python)
}

#' @title Get domain extension (gTLD or ccTLD) from URL or domain name
#'
#' @description Get domain extension from a URL or domain.
#' @param url The URL or domain.
#' @return Return normal domain name in text
#' @import reticulate
#' @export
#' @examples \dontrun{
#' get_domain_extension("example.com")
#' }
#'
get_domain_extension <- function(url){
  get_domain_extension_string = paste("result = ip2whois_init.getDomainExtension('", url, "')", sep = "")
  py_run_string(get_domain_extension_string)
  result_from_python <- py$result
  return(result_from_python)
}



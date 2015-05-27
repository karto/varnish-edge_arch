// 
// Edge Architecture rules for Varnish 4
// http://www.w3.org/TR/2001/NOTE-edge-arch-20010804
// 
// Author Karto Martin <source@karto.net>
// Copyright (c) 2015 Karto Martin. All Right Reserved.
// License The MIT License
//

#######################################################################
# Client side

#sub edge_arch_recv {
#}
#sub edge_arch_pipe {
#}
#sub edge_arch_pass {
#}
#sub edge_arch_hash {
#}
#sub edge_arch_purge {
#}
#sub edge_arch_hit {
#}
#sub edge_arch_miss {
#}
#sub edge_arch_deliver {
#}
#sub edge_arch_synth {
#}


#######################################################################
# Backend Fetch

sub edge_arch_backend_fetch {
    # Send Surrogate-Capability headers to announce ESI support to backend
    if (bereq.http.Surrogate-Capability) {
        set bereq.http.Surrogate-Capability = bereq.http.Surrogate-Capability + ", " + server.identity + {"="Surrogate/1.0 ESI/1.0""};
    }
    else {
        set bereq.http.Surrogate-Capability = server.identity + {"="Surrogate/1.0 ESI/1.0""};
    }
}
sub edge_arch_backend_response {
    
    ###
    # Parse Surrogate-Control for targeted or apply to all content=""
    #
    call edge_arch_set_surrogate_control_content;
    
    ###
    # There are content to process
    #
    if (beresp.http.Surrogate-Control-Content) {
    
        ###
        # Just remove Surrogate/1.0
        #
        if (beresp.http.Surrogate-Control-Content ~ "(?i)(^|\s)Surrogate/1\.0(\s|$)") {
            set beresp.http.Surrogate-Control-Content = regsub(regsub(beresp.http.Surrogate-Control-Content, "(^|\s)Surrogate/1\.0(?=\s|$)", ""), "^\s+", "");
        }
        
        ###
        # Set do_esi and remove ESI/1.0
        #
        if (beresp.http.Surrogate-Control-Content ~ "(?i)(^|\s)ESI/1\.0(\s|$)") {
            set beresp.http.Surrogate-Control-Content = regsub(regsub(beresp.http.Surrogate-Control-Content, "(^|\s)ESI/1\.0(?=\s|$)", ""), "^\s+", "");
            set beresp.do_esi = true;
        }
        
        ###
        # Update Surrogate-Control with changes to targeted or apply to all content=""
        #
        call edge_arch_set_surrogate_control;
        
        ###
        # Remove temp variable
        #
        unset beresp.http.Surrogate-Control-Content;
        
    }
    
}
sub edge_arch_backend_response_cacheable {

    ###
    # Only if caching have not already been determined
    #
    if ( ! beresp.http.X-Cacheable) {
        
        ###
        # Process Surrogate-Control and set X-Cacheable
        #
        call edge_arch_set_x_cacheable;
        
        ###
        # Surrogate-Control has a no-store directive
        #
        if (beresp.http.X-Cacheable ~ "^sc:no-store") {
            set beresp.ttl = 121s;
            set beresp.uncacheable = true;
        }
        
        ###
        # Surrogate-Control has a max-age directive
        #
        elsif (beresp.http.X-Cacheable ~ "^sc:max-age") {
            set beresp.ttl = std.duration(regsub(beresp.http.X-Cacheable, "^.*=(\d*)(\+\d*)?(;.*)?$", "\1")+"s", 0s);
            # Grace period
            if (beresp.http.Surrogate-Control ~ "=\d*\+\d*") {
                set beresp.grace = std.duration(regsub(beresp.http.X-Cacheable, "^.*=\d*\+(\d*)(;.*)?$", "\1")+"s", 0s);
            }
            // https://tools.ietf.org/html/rfc7234#section-4.2
            // half Last-Modified: Sat, 23 May 2015 22:09:02 +0000
            # Calculating Heuristic Grace
            elsif (beresp.http.Last-Modified && std.time(beresp.http.Last-Modified, now) < now) {
                if ((now - std.time(beresp.http.Last-Modified, now)) * 0.5 > beresp.grace && 
                        (now - std.time(beresp.http.Last-Modified, now)) * 0.5 < beresp.keep) {
                    if ("edge_arch_vtc" == server.identity) {
                        set beresp.grace = std.duration(regsub(""+((now - std.time(beresp.http.Last-Modified, now)) * 0.5), "\.\d+$", "s"), 0s);
                    }
                    else {
                        set beresp.grace = (now - std.time(beresp.http.Last-Modified, now)) * 0.5;
                    }
                }
                elsif ((now - std.time(beresp.http.Last-Modified, now)) * 0.5 >= beresp.keep) {
                    set beresp.grace = beresp.keep;
                }
            }
            set beresp.uncacheable = false;
        }
        
    }
}
#sub edge_arch_backend_error {
#}


#######################################################################
# Housekeeping

#sub edge_arch_init {
#}
#sub edge_arch_fini {
#}


#######################################################################
# Each Surrogate Control content

sub edge_arch_set_surrogate_control_content {
    if ("edge_arch_vtc" != server.identity && "www" != server.identity && "drupal" != server.identity) {
        std.log("edge_arch_backend_response: Need configuration to do Surrogate-Control Targeting for "+server.identity+"");
        std.syslog(156, "edge_arch_backend_response: Need configuration to do Surrogate-Control Targeting for "+server.identity+"");
        header.append(beresp.http.Warning, "699 "+server.identity+{" "Need configuration to do Surrogate-Control Targeting for "}+server.identity+{"" ""}+now+{"""});
    }
    if ("edge_arch_vtc" == server.identity && beresp.http.Surrogate-Control ~ {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*;\s*edge_arch_vtc\s*(,|$)"}) {
        set beresp.http.Surrogate-Control-Content = regsub(beresp.http.Surrogate-Control, {"(?i)^(?:.*,)?\s*content\s*=\s*"([^"]*)"\s*;\s*edge_arch_vtc\s*(?:,.*)?$"}, "\1");
    }
    elsif ("www" == server.identity && beresp.http.Surrogate-Control ~ {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*;\s*www\s*(,|$)"}) {
        set beresp.http.Surrogate-Control-Content = regsub(beresp.http.Surrogate-Control, {"(?i)^(?:.*,)?\s*content\s*=\s*"([^"]*)"\s*;\s*www\s*(?:,.*)?$"}, "\1");
    }
    elsif ("drupal" == server.identity && beresp.http.Surrogate-Control ~ {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*;\s*drupal\s*(,|$)"}) {
        set beresp.http.Surrogate-Control-Content = regsub(beresp.http.Surrogate-Control, {"(?i)^(?:.*,)?\s*content\s*=\s*"([^"]*)"\s*;\s*drupal\s*(?:,.*)?$"}, "\1");
    }
    elsif (beresp.http.Surrogate-Control ~ {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*(,|$)"}) {
        set beresp.http.Surrogate-Control-Content = regsub(beresp.http.Surrogate-Control, {"(?i)^(?:.*,)?\s*content\s*=\s*"([^"]*)"\s*(?:,.*)?$"}, "\1");
    }
}

sub edge_arch_set_surrogate_control {
    
    ###
    # Update ;edge_arch_vtc
    #
    if ("edge_arch_vtc" == server.identity && beresp.http.Surrogate-Control ~ {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*;\s*edge_arch_vtc\s*(,|$)"}) {
        # Empty Surrogate-Control so unset
        if (beresp.http.Surrogate-Control-Content ~ "^\s*$" && 
                beresp.http.Surrogate-Control ~ {"(?i)^\s*content\s*=\s*"[^"]*"\s*;\s*edge_arch_vtc\s*$"}) {
            unset beresp.http.Surrogate-Control;
        }
        # Empty Surrogate-Control-Content so remove
        elsif (beresp.http.Surrogate-Control-Content ~ "^\s*$") {
            set beresp.http.Surrogate-Control = regsub(regsub(beresp.http.Surrogate-Control, 
                {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*;\s*edge_arch_vtc\s*(?=,|$)"}, ""), "^\s*(,\s*)?", "");
        }
        # Update changed Surrogate-Control-Content
        elsif (beresp.http.Surrogate-Control-Content != regsub(beresp.http.Surrogate-Control, 
                {"(?i)^(?:.*,)?\s*content\s*=\s*"([^"]*)"\s*;\s*edge_arch_vtc\s*(?:,.*)?$"}, "\1")) {
            set beresp.http.Surrogate-Control = regsub(beresp.http.Surrogate-Control, 
                {"(?i)((?:^|,)\s*content\s*=\s*")[^"]*("\s*;\s*edge_arch_vtc\s*)(?=,|$)"}, 
                "\1"+beresp.http.Surrogate-Control-Content+"\2");
        }
    }
    
    ###
    # Update ;www
    #
    elsif ("www" == server.identity && beresp.http.Surrogate-Control ~ {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*;\s*www\s*(,|$)"}) {
        # Empty Surrogate-Control so unset
        if (beresp.http.Surrogate-Control-Content ~ "^\s*$" && 
                beresp.http.Surrogate-Control ~ {"(?i)^\s*content\s*=\s*"[^"]*"\s*;\s*www\s*$"}) {
            unset beresp.http.Surrogate-Control;
        }
        # Empty Surrogate-Control-Content so remove
        elsif (beresp.http.Surrogate-Control-Content ~ "^\s*$") {
            set beresp.http.Surrogate-Control = regsub(regsub(beresp.http.Surrogate-Control, 
                {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*;\s*www\s*(?=,|$)"}, ""), "^\s*(,\s*)?", "");
        }
        # Update changed Surrogate-Control-Content
        elsif (beresp.http.Surrogate-Control-Content != regsub(beresp.http.Surrogate-Control, 
                {"(?i)^(?:.*,)?\s*content\s*=\s*"([^"]*)"\s*;\s*www\s*(?:,.*)?$"}, "\1")) {
            set beresp.http.Surrogate-Control = regsub(beresp.http.Surrogate-Control, 
                {"(?i)((?:^|,)\s*content\s*=\s*")[^"]*("\s*;\s*www\s*)(?=,|$)"}, 
                "\1"+beresp.http.Surrogate-Control-Content+"\2");
        }
    }
    
    ###
    # Update ;drupal
    #
    elsif ("drupal" == server.identity && beresp.http.Surrogate-Control ~ {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*;\s*drupal\s*(,|$)"}) {
        # Empty Surrogate-Control so unset
        if (beresp.http.Surrogate-Control-Content ~ "^\s*$" && 
                beresp.http.Surrogate-Control ~ {"(?i)^\s*content\s*=\s*"[^"]*"\s*;\s*drupal\s*$"}) {
            unset beresp.http.Surrogate-Control;
        }
        # Empty Surrogate-Control-Content so remove
        elsif (beresp.http.Surrogate-Control-Content ~ "^\s*$") {
            set beresp.http.Surrogate-Control = regsub(regsub(beresp.http.Surrogate-Control, 
                {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*;\s*drupal\s*(?=,|$)"}, ""), "^\s*(,\s*)?", "");
        }
        # Update changed Surrogate-Control-Content
        elsif (beresp.http.Surrogate-Control-Content != regsub(beresp.http.Surrogate-Control, 
                {"(?i)^(?:.*,)?\s*content\s*=\s*"([^"]*)"\s*;\s*drupal\s*(?:,.*)?$"}, "\1")) {
            set beresp.http.Surrogate-Control = regsub(beresp.http.Surrogate-Control, 
                {"(?i)((?:^|,)\s*content\s*=\s*")[^"]*("\s*;\s*drupal\s*)(?=,|$)"}, 
                "\1"+beresp.http.Surrogate-Control-Content+"\2");
        }
    }
    
    ###
    # Update Apply to all
    #
    elsif (beresp.http.Surrogate-Control ~ {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*(,|$)"}) {
        # Empty Surrogate-Control so unset
        if (beresp.http.Surrogate-Control-Content ~ "^\s*$" && 
                beresp.http.Surrogate-Control ~ {"(?i)^\s*content\s*=\s*"[^"]*"\s*$"}) {
            unset beresp.http.Surrogate-Control;
        }
        # Empty Surrogate-Control-Content so remove
        elsif (beresp.http.Surrogate-Control-Content ~ "^\s*$") {
            set beresp.http.Surrogate-Control = regsub(regsub(beresp.http.Surrogate-Control, 
                {"(?i)(^|,)\s*content\s*=\s*"[^"]*"\s*(?=,|$)"}, ""), "^\s*(,\s*)?", "");
        }
        # Update changed Surrogate-Control-Content
        elsif (beresp.http.Surrogate-Control-Content != regsub(beresp.http.Surrogate-Control, 
                {"(?i)^(?:.*,)?\s*content\s*=\s*"([^"]*)"\s*(?:,.*)?$"}, "\1")) {
            set beresp.http.Surrogate-Control = regsub(beresp.http.Surrogate-Control, 
                {"(?i)((?:^|,)\s*content\s*=\s*")[^"]*("\s*)(?=,|$)"}, 
                "\1"+beresp.http.Surrogate-Control-Content+"\2");
        }
    }

}


#######################################################################
# Each Surrogate Control Targeted identities

sub edge_arch_set_x_cacheable {
    
    ###
    # Process ;edge_arch_vtc
    #
    if ("edge_arch_vtc" == server.identity && beresp.http.Surrogate-Control ~ 
            "(?i)(^|,)\s*(no-store|no-store-remote|max-age\s*=\s*\d+(\s*\+\s*\d+)?)\s*;\s*edge_arch_vtc\s*(,|$)") {
        if (beresp.http.Surrogate-Control ~ "(?i)(^|,)\s*no-store\s*;\s*edge_arch_vtc\s*(,|$)") {
            set beresp.http.X-Cacheable = "sc:no-store;edge_arch_vtc";
        }
        elsif (beresp.http.Surrogate-Control ~ "(?i)(^|,)\s*max-age\s*=\s*\d*(\s*\+\s*\d*)?\s*;\s*edge_arch_vtc\s*(,|$)") {
            set beresp.http.X-Cacheable = "sc:max-age="+regsub(beresp.http.Surrogate-Control, 
                "(?i)^(?:.*,)?\s*max-age\s*=\s*(\d*)(?:\s*(\+)\s*(\d*))?\s*;\s*edge_arch_vtc\s*(?:,.*)?$", 
                "\1\2\3")+";edge_arch_vtc";
        }
    }
    ###
    # Process ;www
    #
    elsif ("www" == server.identity && beresp.http.Surrogate-Control ~ 
            "(?i)(^|,)\s*(no-store|no-store-remote|max-age\s*=\s*\d+(\s*\+\s*\d+)?)\s*;\s*www\s*(,|$)") {
        if (beresp.http.Surrogate-Control ~ "(?i)(^|,)\s*no-store\s*;\s*www\s*(,|$)") {
            set beresp.http.X-Cacheable = "sc:no-store;www";
        }
        elsif (beresp.http.Surrogate-Control ~ "(?i)(^|,)\s*max-age\s*=\s*\d*(\s*\+\s*\d*)?\s*;\s*www\s*(,|$)") {
            set beresp.http.X-Cacheable = "sc:max-age="+regsub(beresp.http.Surrogate-Control, 
                "(?i)^(?:.*,)?\s*max-age\s*=\s*(\d*)(?:\s*(\+)\s*(\d*))?\s*;\s*www\s*(?:,.*)?$", 
                "\1\2\3")+";www";
        }
    }
    ###
    # Process ;drupal
    #
    elsif ("drupal" == server.identity && beresp.http.Surrogate-Control ~ 
            "(?i)(^|,)\s*(no-store|no-store-remote|max-age\s*=\s*\d+(\s*\+\s*\d+)?)\s*;\s*drupal\s*(,|$)") {
        if (beresp.http.Surrogate-Control ~ "(?i)(^|,)\s*no-store\s*;\s*drupal\s*(,|$)") {
            set beresp.http.X-Cacheable = "sc:no-store;drupal";
        }
        elsif (beresp.http.Surrogate-Control ~ "(?i)(^|,)\s*max-age\s*=\s*\d*(\s*\+\s*\d*)?\s*;\s*drupal\s*(,|$)") {
            set beresp.http.X-Cacheable = "sc:max-age="+regsub(beresp.http.Surrogate-Control, 
                "(?i)^(?:.*,)?\s*max-age\s*=\s*(\d*)(?:\s*(\+)\s*(\d*))?\s*;\s*drupal\s*(?:,.*)?$", 
                "\1\2\3")+";drupal";
        }
    }
    ###
    # Process apply to all others
    #
    elsif (beresp.http.Surrogate-Control ~ "(?i)(^|,)\s*(no-store|no-store-remote|max-age\s*=\s*\d+(\s*\+\s*\d+)?)\s*(,|$)") {
        if (beresp.http.Surrogate-Control ~ "(?i)(^|,)\s*no-store\s*(,|$)") {
            set beresp.http.X-Cacheable = "sc:no-store";
        }
        elsif (beresp.http.Surrogate-Control ~ "(?i)(^|,)\s*max-age\s*=\s*\d*(\s*\+\s*\d*)?\s*(,|$)") {
            set beresp.http.X-Cacheable = "sc:max-age="+regsub(beresp.http.Surrogate-Control, 
                "(?i)^(?:.*,)?\s*max-age\s*=\s*(\d*)(?:\s*(\+)\s*(\d*))?\s*(?:,.*)?$", 
                "\1\2\3")+";edge_arch_vtc";
        }
    }
}

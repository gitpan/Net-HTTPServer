##############################################################################
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Library General Public
#  License as published by the Free Software Foundation; either
#  version 2 of the License, or (at your option) any later version.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Library General Public License for more details.
#
#  You should have received a copy of the GNU Library General Public
#  License along with this library; if not, write to the
#  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
#  Boston, MA  02111-1307, USA.
#
#  Copyright (C) 2003 Ryan Eatmon
#
##############################################################################
package Net::HTTPServer;

=head1 NAME

Net::HTTPServer

=head1 SYNOPSIS

Net::HTTPServer provides a lite HTTP server.  It can serve files, or can
be configured to call Perl functions when a URL is accessed.
  
=head1 DESCRIPTION

Net::HTTPServer basically turns a CGI script into a stand alone server.
Useful for temporary services, mobile/local servers, or embedding an HTTP
server into another program.

=head1 EXAMPLES

use Net::HTTPServer;

my $server = new Net::HTTPServer(port=>5000,
                                 docroot=>"/var/www/site");

$server->Start();

$server->Process();  # Run forever

   or

while(1)
{
    $server->Process(5);  # Run for 5 seconds
    # Do something else...
}

$server->Stop();


=head1 METHODS

=head2 new(%cfg)

Given a config hash, return a server object that you can start, process,
and stop.  The config hash takes the options:

    chroot => 0|1       - Run the server behind a virtual chroot().
                          Since only root can actually call chroot,
                          a URL munger is provided that will not
                          allow URLs to go beyond the document root
                          if this is specified.
                          ( Default: 1 )

    docroot => string   - Path on the filesystem that you want to be
                          the document root "/" for the server.
                          ( Default: "." )

    index => list       - Specify a list of file names to use as the
                          the index file when a directory is requested.
                          ( Default: ["index.html","index.htm"] )

    log => string       - Path to store the log at.  If you set this to
                          "STDOUT" then it will display to STDOUT.
                          ( Default: access.log )

    mimetypes => string - Path to an alternate mime.types file.
                          ( Default: included in release )

    numproc => int      - When type is set to "forking", this tells the
                          server how many child processes to keep
                          running at all times.
                          ( Default: 5 )
                                 
    port => int         - Port number to use.  You can optionally
                          specify the string "scan", and the server
                          will loop through ports until it finds one
                          it can listen on.  This port is then returned
                          by the Start() method.
                          ( Default: 9000 )

    ssl => 0|1          - Run a secure server using SSL.  You must
                          specify ssl_key, ssl_cert, and ssl_ca if
                          set this to 1.
                          ( Default: 0 )

    ssl_ca => string    - Path to the SSL ca file.
                          ( Default: undef )

    ssl_cert => string  - Path to the SSL cert file.
                          ( Default: undef )

    ssl_key => string   - Path to the SSL key file.
                          ( Default: undef )

    type => string      - What kind of server to create?  Available
                          types are:
                            single  - single process/no forking
                            forking - preforking server
                          (Default: "single")


=head2 AddServerTokens(token,[token,...])

Adds one or more tokens onto the Server header line that the server sends
back in a response.  The list is seperated by a ; to distinguish the
various tokens from each other.

  $server->AddServerTokens("test/1.3")l

This would result in the following header being sent in a response:

HTTP/1.1 200
Server: Net::HTTPServer/0.9 test/1.3
Content-Type: text/html
...

=head2 Process(timeout)

Listens for incoming requests and responds back to them.  This function
will block, unless a timeout is specified, then it will block for that
number of seconds before returning.  Useful for embedding this into
other programs and still letting the other program get some CPU time.

=head2 RegisterAuth(method,url,realm,function)

Protect the URL using the Authentication method provided.  The supported
methods are: "Basic" and "Digest".

When a URL with a path component that matchs the specified URL is
requested the server requests that the client perform the specified
of authentication for the given realm.  When the URL is accessed the
second time, the client provides the authentication pieces and the
server parses the pieces and using the return value from the specified
function answers the request.  The function is called with the username
and the URL they are trying to access.  It is required that the function
return a two item list with a return code and the users's password.

The valid return codes are:

  200   The user exists and is allowed to access
        this URL.  Return the password.
        return( "200", password )

  401   The user does not exist.  Obviously you
        do not have to return a password in this
        case.
        return( "401" )

  403   The user is forbidden to access this URL.
        (You must still return the password because
        if the user did not auth, then we do not want
        to tip off the bad people that this username
        is valid.)
        return( "403", password )

The reasoning for having the function return the password is that Digest
authentication is just complicated enough that asking you to write part of
logic would be considered rude.  By just having you give the server the
password we can keep the whole Auth interface simple.

Here is an example:

  $server->RegisterAuth("Basic","/foo/bar.pl","Secure",\&testBasic);

  sub testBasic
  {
      my $url = shift;
      my $user = shift;

      my $password = &lookupPassword($user);
      
      return("401","") unless defined($password);
      
      if (($url eq "/foo/bar.pl") && ($user eq "dr_evil"))
      {
          return ("403",$password);
      }

      return ("200",$password);
  }

  sub lookupPassword
  {
      my $user = shift;

      my %passwd;
      $passwd{larry}   = "wall";
      $passwd{dr_evil} = "1million";

      return unless exists($passwd{$user});
      return $passwd{$user};
  }

Start a server with that, and the following RegisterURL example,
and point your browser to:

  http://localhost:9000/foo/bar.pl?test=bing&test2=bong

You should be prompted for a userid and password, entering "larry"
and "wall"  will allow you to see the page.  Entering "dr_evil" and
"1million" should result in getting a Forbidden page (and likely
needing to restart your browser).  Entering any other userid or
password should result in you being asked again.

If you have a handler for both RegisterURL and RegisterAuth, then
your function for RegisterURL can find the identify of the user in
the C<$env-E<gt>{'REMOTE_USER'}> hash entry. This is similar to CGI
scripts.

You can have multiple handlers for different URLs. If you do this,
then the longest complete URL handler will be called. For example,
if you have handlers for C</foo/bar.pl> and C</foo>, and a URL
of C</foo/bar.pl> is called, then the handler C</foo/bar.pl> is
called to authorize this request, but if a URL of C</foo/bar.html>
is called, then the handler C</foo> is called.

Only complete directories are matched, so if you had a handler for
C</foo/bar>, then it would not be called for either /foo/bar.pl or
C</foo/bar.html>.

=head2 RegisterURL(url,function)

Register the function with the provided URL.  When that URL is requested,
the function is called and passed in the environment (GET+POST) so that
it can do something meaningful with them.  A simple handler looks like:

  $server->RegisterURL("/foo/bar.pl",\&test);

  sub test
  {
      my $env = shift;  # hash reference

      my $res;
      $res  = "<html>\n";
      $res .= "  <head>\n";
      $res .= "    <title>This is a test</title>\n";
      $res .= "  </head>\n";
      $res .= "  <body>\n";
      $res .= "    <pre>\n";

      foreach my $var (keys(%{$env}))
      {
          $res .= "$var -> ".$env->{$var}."\n";
      }
      
      $res .= "    </pre>\n";
      $res .= "  </body>\n";
      $res .= "</html>\n";

      return ["200",   # HTTP Response code (200 = Ok)
              {},      # Headers to send back
              $res     # Whatever you are sending back
             ];
  }
  
Start a server with that and point your browser to:

  http://localhost:9000/foo/bar.pl?test=bing&test2=bong

You should see a page titled "This is a test" with this body:

  test -> bing
  test2 -> bong

=head2 Start()

Starts the server based on the config options passed to new().  Returns
the port number the server is listening on, or undef if the server was
unable to start.

=head2 Stop()

Shuts down the socket connection and cleans up after itself.

=head1 AUTHOR

Ryan Eatmon

=head1 COPYRIGHT

This module is free software, you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
  
use strict;
use Carp;
use URI;
use URI::QueryParam;
use IO::Socket;
use IO::Select;
use FileHandle;
use POSIX;

use vars qw ( $VERSION %ALLOWED $SSL $Base64 $DigestMD5 );

$VERSION = "0.9.1";

$ALLOWED{GET} = 1;
$ALLOWED{HEAD} = 1;
$ALLOWED{POST} = 1;
$ALLOWED{TRACE} = 1;

#------------------------------------------------------------------------------
# Do we have IO::Socket::SSL for https support?
#------------------------------------------------------------------------------
if (eval "require IO::Socket::SSL;")
{
    require IO::Socket::SSL;
    import IO::Socket::SSL;
    $SSL = 1;
}
else
{
    $SSL = 0;
}

#------------------------------------------------------------------------------
# Do we have MIME::Base64 for Basic Authentication support?
#------------------------------------------------------------------------------
if (eval "require MIME::Base64;")
{
    require MIME::Base64;
    import MIME::Base64;
    $Base64 = 1;
}
else
{
    $Base64 = 0;
}

#------------------------------------------------------------------------------
# Do we have Digest::MD5 for Digest Authentication support?
#------------------------------------------------------------------------------
if (eval "require Digest::MD5;")
{
    require Digest::MD5;
    import Digest::MD5;
    $DigestMD5 = 1;
}
else
{
    $DigestMD5 = 0;
}


sub new
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = { };
    
    bless($self, $proto);

    my (%args) = @_;

    $self->{ARGS} = \%args;

    $self->{CFG}->{CHROOT}    = $self->_arg("chroot",1);
    $self->{CFG}->{DOCROOT}   = $self->_arg("docroot",".");
    $self->{CFG}->{INDEX}     = $self->_arg("index",["index.html","index.htm"]);
    $self->{CFG}->{LOG}       = $self->_arg("log","access.log");
    $self->{CFG}->{NUMPROC}   = $self->_arg("numproc",5);
    $self->{CFG}->{MIMETYPES} = $self->_arg("mimetypes",undef);
    $self->{CFG}->{PORT}      = $self->_arg("port",9000);
    $self->{CFG}->{SSL}       = $self->_arg("ssl",0) && $SSL;
    $self->{CFG}->{SSL_KEY}   = $self->_arg("ssl_key",undef);
    $self->{CFG}->{SSL_CERT}  = $self->_arg("ssl_cert",undef);
    $self->{CFG}->{SSL_CA}    = $self->_arg("ssl_ca",undef);
    $self->{CFG}->{TYPE}      = $self->_arg("type","single");

    if ($self->{CFG}->{LOG} eq "STDOUT")
    {
        $self->{LOG} = \*STDOUT;
    }
    else
    {
        $self->{LOG} = new FileHandle(">>$self->{CFG}->{LOG}");
        if (!defined($self->{LOG}))
        {
            croak("Could not open log $self->{CFG}->{LOG} for append:\n    $!");
        }
    }
    FileHandle::autoflush($self->{LOG},1);

    $self->{DEBUG} = {};
    if (exists($self->{ARGS}->{debug}))
    {
        $| = 1;

        foreach my $zone (@{$self->{ARGS}->{debug}})
        {
            $self->{DEBUG}->{$zone} = 1;
        }
    }

    delete($self->{ARGS});

    if (!defined($self->{CFG}->{MIMETYPES}))
    {
        foreach my $lib (@INC)
        {
            if (-e "$lib/Net/HTTPServer/mime.types")
            {
                $self->{CFG}->{MIMETYPES} = "$lib/Net/HTTPServer/mime.types";
                last;
            }
        }
    }
    
    $self->_mimetypes();
    
    if ($DigestMD5)
    {
        $self->{PRIVATEKEY} = Digest::MD5::md5_hex("Net::HTTPServer/$VERSION".time);
    }

    $self->{AUTH} = {};
    $self->{CALLBACKS} = {};
    $self->{SERVER_TOKENS} = [ "Net::HTTPServer/$VERSION" ];

    return $self;
}


###############################################################################
#
# AddServerTokens - Add more tokens that will be sent on the Server: header
#                  line of a response.
#
###############################################################################
sub AddServerTokens
{
    my $self = shift;
    my (@tokens) = @_;

    foreach my $token (@tokens)
    {
        if ($token =~ / /)
        {
            croak("Server token cannot contain any spaces: \"$token\"");
        }
    
        push(@{$self->{SERVER_TOKENS}},$token);
    }
}


###############################################################################
#
# Process - Inner loop to handle connection, read requests, process them, and
#           respond.
#
###############################################################################
sub Process
{
    my $self = shift;
    my $timeout = shift;

    if (!defined($self->{SOCK}))
    {
        croak("Process() called on undefined socket.  Check the result from Start().\n    ");
    }

    my $timestop = undef;
    $timestop = time + $timeout if defined($timeout);
    
    $self->_debug("PROC","Process: type($self->{CFG}->{TYPE})");

    my $block = 1;
    while($block)
    {
        if ($self->{CFG}->{TYPE} eq "single")
        {
            $self->_single_process($timestop);
        }
        elsif ($self->{CFG}->{TYPE} eq "forking")
        {
            $self->_forking_process();
        }

        $block = 0 if (defined($timestop) && (($timestop - time) <= 0));
    }
}


###############################################################################
#
# RegisterAuth - Protect the given URL using the given authentication method
#                and calling the supplied function to verify the username
#                and password.
#
###############################################################################
sub RegisterAuth
{
    my $self = shift;
    my $method = shift;
    my $url = shift;
    my $realm = shift;
    my $callback = shift;

    $method = lc($method);
    
    if (($method ne "basic") && ($method ne "digest"))
    {
        croak("You did not specify a valid method to RegisterAuth: \"$method\"\nValid options are:\n    basic, digest\n");
    }

    if (($method eq "basic") || ($method eq "digest"))
    {
	    if (!$Base64)
        {
            $self->_log("Cannot register authentication callback as MIME::Base64 is not installed...");
            carp("Cannot register authentication callback as MIME::Base64 is not installed...");
        }
    }
    
    if ($method eq "digest")
    {
	    if (!$DigestMD5)
        {
            $self->_log("Cannot register authentication callback as Digest::MD5 is not installed...");
            carp("Cannot register authentication callback as Digest::MD5 is not installed...");
        }
    }
    
    $self->{AUTH}->{$url}->{method}   = $method;
    $self->{AUTH}->{$url}->{realm}    = $realm;
    $self->{AUTH}->{$url}->{callback} = $callback;
}


###############################################################################
#
# RegisterURL - given a URL path, call the supplied function when it is
#               requested.
#
###############################################################################
sub RegisterURL
{
    my $self = shift;
    my $url = shift;
    my $callback = shift;

    $self->{CALLBACKS}->{$url} = $callback;
}


###############################################################################
#
# Start - Just a little initialization routine to start the server.
#
###############################################################################
sub Start
{
    my $self = shift;

    $self->_debug("INIT","Start: Starting the server");

    my $port = $self->{CFG}->{PORT};
    my $scan = ($port eq "scan" ? 1 : 0);
    $port = 8000 if $scan;
    
    $self->{SOCK} = undef;

    while(!defined($self->{SOCK}))
    {
        $self->_debug("INIT","Start: Attempting to listen on port $port");
        
        if ($self->{CFG}->{SSL} == 0)
        {
            $self->{SOCK} = new IO::Socket::INET(LocalPort=>$port,
                                                 Proto=>"tcp",
                                                 Listen=>10,
                                                 Reuse=>1,
                                                 Blocking=>0);
        }
        else
        {
            if (!defined($self->{CFG}->{SSL_KEY}) ||
                !defined($self->{CFG}->{SSL_CERT}) ||
                !defined($self->{CFG}->{SSL_CA}))
            {
                croak("You must specify ssl_key, ssl_cert, and ssl_ca if you want to use SSL.");
                return;
            }
            $self->_debug("INIT","Start: Create an SSL socket.");
            $self->{SOCK} = new IO::Socket::SSL(LocalPort=>$port,
                                                Proto=>"tcp",
                                                Listen=>10,
                                                Reuse=>1,
                                                Blocking=>0,
                                                SSL_key_file=>$self->{CFG}->{SSL_KEY},
                                                SSL_cert_file=>$self->{CFG}->{SSL_CERT},
                                                SSL_ca_file=>$self->{CFG}->{SSL_CA},
                                                SSL_verify_mode=> 0x01,
                                               );
        }
        last if defined($self->{SOCK});
        last if ($port == 9999);
        last if !$scan;
        
        $port++;
    }

    if (!defined($self->{SOCK}))
    {
        $self->_log("Could not start the server...");
        if ($self->{CFG}->{SSL} == 0)
        {
            carp("Could not start the server: $!");
        }
        else
        {
            carp("Could not start the server: ",&IO::Socket::SSL::errstr);
        }

        return;
    }

    $self->{SELECT} = new IO::Select($self->{SOCK});

    if ($self->{CFG}->{TYPE} eq "forking")
    {
        $self->_debug("INIT","Start: Initializing forking");
        $SIG{CHLD} = sub{ $self->_forking_reaper(); };
        $self->{CHILDREN} = {};
        $self->{NUMCHILDREN} = 0;
    }
    
    $self->_log("Server running on port $port");

    return $port;
}


###############################################################################
#
# Stop - Stop the server.
#
###############################################################################
sub Stop
{
    my $self = shift;

    $self->_debug("INIT","Stop: Stopping the server");

    if ($self->{CFG}->{TYPE} eq "forking")
    {
        $self->_forking_huntsman();
    }
    
    if (exists($self->{SELECT}) && defined($self->{SELECT}))
    {
        $self->{SELECT}->remove($self->{SOCK});
    }

    if (exists($self->{SOCK}) && defined($self->{SOCK}))
    {
        $self->{SOCK}->close();
    }
}




###############################################################################
#+-----------------------------------------------------------------------------
#| Private Flow Functions
#+-----------------------------------------------------------------------------
###############################################################################

###############################################################################
#
# _HandleAuth - Make sure that the user has passed the authentication to view
#               this page.
#
###############################################################################
sub _HandleAuth
{
    my $self = shift;
    my $url = shift;
    my $headers = shift;
    my $env = shift;

    my $authURL = $self->_checkAuth($url);
    return unless defined($authURL);

    $self->_debug("AUTH","_HandleAuth: url($url)");
    $self->_debug("AUTH","_HandleAuth: authURL($authURL) method($self->{AUTH}->{$authURL}->{method})");

    if ($self->{AUTH}->{$authURL}->{method} eq "basic")
    {
        return $self->_HandleAuthBasic($authURL,$url,$headers,$env);
    }
    elsif ($self->{AUTH}->{$authURL}->{method} eq "digest")
    {
        return $self->_HandleAuthDigest($authURL,$url,$headers,$env);
    }

    return;
}


###############################################################################
#
# _HandleAuthBasic - Parse the Authentication header and make sure that the
#                    user is allowed to see this page.
#
###############################################################################
sub _HandleAuthBasic
{
    my $self = shift;
    my $authURL = shift;
    my $url = shift;
    my $headers = shift;
    my $env = shift;

    my $realm = $self->{AUTH}->{$authURL}->{realm};

    $self->_debug("AUTH","_HandleAuthBasic: authURL($authURL) realm($realm)");

    #-------------------------------------------------------------------------
    # Auth if they did not send an Authorization
    #-------------------------------------------------------------------------
    return $self->_AuthBasic($realm) if !exists($headers->{Authorization});
    $self->_debug("AUTH","_HandleAuthBasic: there was an Authorization");

    my ($method,$base64) = split(" ",$headers->{Authorization},2);

    #-------------------------------------------------------------------------
    # Auth if they did not send a Basic Authorization
    #-------------------------------------------------------------------------
    return $self->_AuthBasic($realm) if (lc($method) ne "basic");
    $self->_debug("AUTH","_HandleAuthBasic: it was a Basic");

    my ($user,$password) = split(":",MIME::Base64::decode($base64));

    my ($code,$real_password) =
        &{$self->{AUTH}->{$authURL}->{callback}}($url,$user);
    $self->_debug("AUTH","_HandleAuthBasic: callback return code($code)");

    #-------------------------------------------------------------------------
    # Return the results of the authentication handler
    #-------------------------------------------------------------------------
    return $self->_AuthBasic($realm) if ($code eq "401");
    return $self->_AuthBasic($realm) if ($password ne $real_password);
    return $self->_Forbidden() if ($code eq "403");

    #-------------------------------------------------------------------------
    # We authed, so set REMOTE_USER in the env hash and return
    #-------------------------------------------------------------------------
    $env->{'REMOTE_USER'} = $user;
    return;
}


###############################################################################
#
# _HandleAuthDigest - Parse the Authentication header and make sure that the
#                     user is allowed to see this page.
#
###############################################################################
sub _HandleAuthDigest
{
    my $self = shift;
    my $authURL = shift;
    my $url = shift;
    my $headers = shift;
    my $env = shift;

    my %digest;
    $digest{algorithm} = "MD5";
    $digest{nonce} = $self->_nonce();
    $digest{realm} = $self->{AUTH}->{$authURL}->{realm};
    $digest{qop} = "auth";

    $self->_debug("AUTH","_HandleAuthDigest: authURL($authURL) realm($digest{realm})");

    #-------------------------------------------------------------------------
    # Auth if they did not send an Authorization
    #-------------------------------------------------------------------------
    return $self->_AuthDigest(\%digest) if !exists($headers->{Authorization});
    $self->_debug("AUTH","_HandleAuthDigest: there was an Authorization");

    my ($method,$directives) = split(" ",$headers->{Authorization},2);

    #-------------------------------------------------------------------------
    # Auth if they did not send a Digest Authorization
    #-------------------------------------------------------------------------
    return $self->_AuthDigest(\%digest) if (lc($method) ne "digest");
    $self->_debug("AUTH","_HandleAuthDigest: it was a Digest");

    my %authorization;
    foreach my $directive (split(",",$directives))
    {
        my ($key,$value) = ($directive =~ /^\s*([^=]+)\s*=\s*\"?(.+?)\"?\s*$/);
        $authorization{$key} = $value;
    }
    
    #-------------------------------------------------------------------------
    # Make sure that the uri in the auth and the request are the same.
    #-------------------------------------------------------------------------
    return $self->_BadRequest() if ($url ne $authorization{uri});

    my ($code,$real_password) =
        &{$self->{AUTH}->{$authURL}->{callback}}($url,$authorization{username});
    $self->_debug("AUTH","_HandleAuthDigest: callback return code($code)");

    my $ha1 = $self->_digest_HA1(\%authorization,$real_password);
    my $ha2 = $self->_digest_HA2(\%authorization,$headers->{'__METHOD__'});
    my $kd = $self->_digest_KD(\%authorization,$ha1,$ha2);

    #-------------------------------------------------------------------------
    # Return the results of the authentication handler
    #-------------------------------------------------------------------------
    return $self->_AuthDigest(\%digest) if ($code eq "401");
    return $self->_AuthDigest(\%digest) if ($kd ne $authorization{response});
    return $self->_Forbidden() if ($code eq "403");

    #-------------------------------------------------------------------------
    # If they authed, then check over the nonce and make sure it's valid.
    #-------------------------------------------------------------------------
    my ($time,$privatekey) = split(":",MIME::Base64::decode($authorization{nonce}));

    if ($privatekey ne $self->{PRIVATEKEY})
    {
        $self->_debug("AUTH","_HandleAuthDigest: nonce is stale due to key.");
        $digest{stale} = "TRUE";
        return $self->_AuthDigest(\%digest)
    }

    if ((time - $time) > 30)
    {
        $self->_debug("AUTH","_HandleAuthDigest: nonce is stale due to time.");
        $digest{stale} = "TRUE";
        return $self->_AuthDigest(\%digest);
    }
    
    # XXX - check nc for replay attack
    # XXX - better nonce to minimize replay attacks?
    
    #-------------------------------------------------------------------------
    # We authed, so set REMOTE_USER in the env hash and return
    #-------------------------------------------------------------------------
    $env->{'REMOTE_USER'} = $authorization{username};
    return;
}


###############################################################################
#
# _ProcessRequest - Based on the URL and Environment, figure out what they
#                   wanted, and call the correct handler.
#
###############################################################################
sub _ProcessRequest
{
    my $self = shift;
    my $url = shift;
    my $headers = shift;
    my $env = shift;

    #-------------------------------------------------------------------------
    # Catch some common errors/reponses without doing any real hard work
    #-------------------------------------------------------------------------
    return @{$self->_MethodNotAllowed()} if !exists($ALLOWED{$headers->{'__METHOD__'}});
    return @{$self->_ExpectationFailed()} if exists($headers->{Expect});
    return ("200",{},"") if ($headers->{'__METHOD__'} eq "TRACE");

    $url = $self->_chroot($url);

    my $response;

    if (exists($self->{CALLBACKS}->{$url}))
    {
        my $auth = $self->_HandleAuth($url,$headers,$env);
        return @{$auth} if defined($auth);

        $self->_debug("PROC","_ProcessRequest: Callback");
        $response = &{$self->{CALLBACKS}->{$url}}($env);
    }
    elsif (-e $self->{CFG}->{DOCROOT}."/$url")
    {
        my $auth = $self->_HandleAuth($url,$headers,$env);
        return @{$auth} if defined($auth);

        $self->_debug("PROC","_ProcessRequest: File");
        $response = $self->_ServeFile($url);        
    }
    else
    {
        $self->_debug("PROC","_ProcessRequest: Not found");
        $response = $self->_NotFound();
    }

    return @{$response};
}


###############################################################################
#
# _ReadRequest - Take the full request, pull out the type, url, GET, POST, etc.
#
###############################################################################
sub _ReadRequest
{
    my $self = shift;
    my $request = shift;
    
    my %headers;
    my %env;

    my ($method,$url) = ($request =~ /(\S+)\s+(\S+)\s+/s);
    
    $self->_debug("REQ","_ReadRequest: method($method) url($url)");
    $self->_log("$method $url");

    $headers{'__TRACE__'} = $request if ($method eq "TRACE");
    
    my ($headers,$body) = ($request =~ /^(.+?)\r?\n\r?\n(.*?)$/s);
    $self->_debug("REQ","_ReadRequest: headers($headers)");
    $self->_debug("REQ","_ReadRequest: body($body)");

    foreach my $header (split("\n",$headers))
    {
        my ($key,$value) = ($header =~ /^([^\:]+)\s*\:\s*(.+)\s*$/);
        next unless defined($key);

        $headers{$key} = $value;
    }

    $headers{'__METHOD__'} = $method;
    
    my $uri = new URI($url,"http");

    my $path = $uri->path();

    foreach my $key ($uri->query_param())
    {
        $env{$key} = $uri->query_param($key);
    }

    if ($method eq "POST")
    {
        $self->_debug("REQ","_ReadRequest: We got a POST");

        my $post_uri = new URI("?$body","http");

        foreach my $key ($post_uri->query_param())
        {
            $env{$key} = $post_uri->query_param($key);
            $self->_debug("REQ","_ReadRequest: ENV: $key: $env{$key}");
        }
    }
    
    return ( $path, \%headers, \%env );
}


###############################################################################
#
# _ReturnResponse - Take all of the pieces and generate the reponse, and send
#                   it out.
#
###############################################################################
sub _ReturnResponse
{
    my $self = shift;
    my $client = shift;
    my $reqheaders = shift;
    my $code = shift;
    my $headers = shift;
    my $response = shift;

    #-------------------------------------------------------------------------
    # Initialize the content type
    #-------------------------------------------------------------------------
    $headers->{'Content-Type'} = "text/html"
        unless exists($headers->{'Content-Type'});
    
    #-------------------------------------------------------------------------
    # Check that it's acceptable to the client
    #-------------------------------------------------------------------------
    if (exists($reqheaders->{'Accept'}))
    {
        if (!$self->_accept($reqheaders->{Accept},$headers->{'Content-Type'}))
        {
            ($code,$headers,$response) = @{$self->_NotAcceptable()};
        }
    }

    #-------------------------------------------------------------------------
    # Initialize any missing (and required) headers
    #-------------------------------------------------------------------------
    $headers->{'Accept-Ranges'} = "none";
    $headers->{'Allow'} = join(", ",keys(%ALLOWED));
    $headers->{'Content-Length'} = length($response)
        unless exists($headers->{'Content-Length'});
    $headers->{'Connection'} = "close";
    $headers->{'Date'} = $self->_date();
    $headers->{'Server'} = join(" ",@{$self->{SERVER_TOKENS}});
    
    #-------------------------------------------------------------------------
    # If this was a HEAD, then there is no response
    #-------------------------------------------------------------------------
    $response = "" if ($reqheaders->{'__METHOD__'} eq "HEAD");
    
    if ($reqheaders->{'__METHOD__'} eq "TRACE")
    {
        $headers->{'Content-Type'} = "message/http";
        $response = $reqheaders->{'__TRACE__'};
    }

    #-------------------------------------------------------------------------
    # Format the return headers
    #-------------------------------------------------------------------------
    my $header = "HTTP/1.1 $code\n";
    foreach my $key (keys(%{$headers}))
    {
        $header .= "$key: ".$headers->{$key}."\n";
    }
    chomp($header);
    $header .= "\r\n\r\n";

    #-------------------------------------------------------------------------
    # Debug
    #-------------------------------------------------------------------------
    $self->_debug("RESP","_ReturnResponse: ----------------------------------------");
    $self->_debug("RESP","_ReturnResponse: $header");
    if (($headers->{'Content-Type'} eq "text/html") ||
        ($headers->{'Content-Type'} eq "text/plain"))
    {
        $self->_debug("RESP","_ReturnResponse: $response");
    }
    $self->_debug("RESP","_ReturnResponse: ----------------------------------------");
    
    #-------------------------------------------------------------------------
    # Send the headers and response
    #-------------------------------------------------------------------------
    return unless defined($self->_send($client,$header));
    return unless defined($self->_send($client,$response));
}


###############################################################################
#
# _ServeFile - If they asked for a valid file in the file system, then we need
#              to suck it in, profile it, and ship it back out.
#
###############################################################################
sub _ServeFile
{
    my $self = shift;
    my $path = shift;

    my $fullpath = $self->{CFG}->{DOCROOT}."/$path";

    if (-d $fullpath)
    {
        $self->_debug("FILE","_ServeFile: This is a directory, look for an index file.");
        my $match = 0;
        foreach my $index (@{$self->{CFG}->{INDEX}})
        {
            if (-f $fullpath."/".$index)
            {
                $match = 1;
                $fullpath .= "/$index";
                $fullpath =~ s/\/+/\//g;
                last;
            }
        }
        
        if ($match == 0)
        {
            if ($path !~ /\/$/)
            {
                return $self->_Redirect($path."/");
            }

            $self->_debug("FILE","_ServeFile: Show a directory listing.");
            return $self->_DirList($path);
        }
    }

    if (!(-f $fullpath))
    {
        $self->_debug("FILE","_ServeFile: 404, File not found.  Whoop! Whoop!");
        return $self->_NotFound();
    }

    my %headers;

    my $fileHandle = new FileHandle($fullpath);
    return $self->_NotFound() unless defined($fileHandle);

    my ($ext) = ($fullpath =~ /\.([^\.]+?)$/);
    if (($ext ne "") && exists($self->{MIMETYPES}->{$ext}))
    {
        $headers{'Content-Type'} = $self->{MIMETYPES}->{$ext};
    }
    elsif (-T $fullpath)
    {
        $headers{'Content-Type'} = $self->{MIMETYPES}->{txt};
    }

    $headers{'Content-Length'} = (stat( $fullpath ))[7];
    $headers{'Last-Modified'} = $self->_date((stat( $fullpath ))[9]);

    return ["200",\%headers,$fileHandle];
}




###############################################################################
#+-----------------------------------------------------------------------------
#| Private Canned Responses
#+-----------------------------------------------------------------------------
###############################################################################

###############################################################################
#
# _Auth - Send an authentication response
#
###############################################################################
sub _Auth
{
    my $self = shift;
    my $method = shift;
    my $args = shift;

    my @directives = "";

    foreach my $key (keys(%{$args}))
    {
        push(@directives,$key.'="'.$args->{$key}.'"');
    }

    my $directives = join(",",@directives);
    
    return $self->_Error("401",
                         { 'WWW-Authenticate' => "$method $directives" },
                         "Unauthorized",
                         "Authorization is required to access this object on this server."
                        );
}


###############################################################################
#
# _AuthBasic - Send a Basic authentication response
#
###############################################################################
sub _AuthBasic
{
    my $self = shift;
	my $realm = shift;

    return $self->_Auth("Basic",{ realm=>$realm });
}


###############################################################################
#
# _AuthDigest - Send a Digest authentication response
#
###############################################################################
sub _AuthDigest
{
    my $self = shift;
	my $args = shift;

    return $self->_Auth("Digest",$args);
}


###############################################################################
#
# _BadRequest - 400, someone was being naughty
#
###############################################################################
sub _BadRequest
{
    my $self = shift;

    return $self->_Error("400",
                         {},
                         "Bad Request",
                         "You made a bad request.  Somthing you sent did not match up.",
                        );
}


###############################################################################
#
# _DirList - If they want a directory... let's give them a directory.
#
###############################################################################
sub _DirList
{
    my $self = shift;
    my $path = shift;

    my $res = "<html><head><title>Dir listing for $path</title></head><body>\n";
    
    opendir(DIR,$self->{CFG}->{DOCROOT}."/".$path);
    foreach my $file (sort {$a cmp $b} readdir(DIR))
    {
        next if ($file eq ".");
        next if (($file eq "..") && ($path eq "/"));

        if ($file =~ /\:/)
        {
            $res .= "<a href='${path}${file}'>$file</a><br/>\n";
        }
        else
        {
            $res .= "<a href='$file'>$file</a><br/>\n";
        }
    }

    $res .= "</body></html>\n";

    return ["200",{},$res];
}


###############################################################################
#
# _Error - take a code, headers, error string, and text and return a standard
#          response.
#
###############################################################################
sub _Error
{
    my $self = shift;
    my $code = shift;
    my $headers = shift;
    my $string = shift;
    my $body = shift;

    my $response = "<html>";
    $response .= "<head><title>".$string."!</title></head>";
    $response .= "<body bgcolor='#FFFFFF' text='#000000' link='#0000CC'>";
    $response .= "<h1>".$string."!</h1>";
    $response .= "<dl><dd>".$body."</dd></dl>";
    $response .= "<h2>Error ".$code."</h2>";
    $response .= "</body>";
    $response .= "</html>";

    return [$code,$headers,$response];
}


###############################################################################
#
# _ExpectationFailed - 417, sigh... I never meet anyone's expectations
#
###############################################################################
sub _ExpectationFailed
{
    my $self = shift;

    return $self->_Error("400",
                         {},
                         "Expectation Failed",
                         "The server could not meet the expectations you had for it."
                        );
}


###############################################################################
#
# _Forbidden - ahhh the equally dreaded 403
#
###############################################################################
sub _Forbidden
{
    my $self = shift;

    return $self->_Error("403",
                         {},
                         "Forbidden",
                         "You do not have permission to access this object on this server.",
                        );
}


###############################################################################
#
# _MethodNotAllowed - 405... you must only do what is allowed
#
###############################################################################
sub _MethodNotAllowed
{
    my $self = shift;

    return $self->_Error("405",
                         {},
                         "Method Not Allowed",
                         "You are not allowed to do what you just tried to do..."
                        );
}


###############################################################################
#
# _NotAcceptable - the client is being inflexiable... they won't accept what
#                  we want to send.
#
###############################################################################
sub _NotAcceptable
{
    my $self = shift;

    return $self->_Error("406",
                         {},
                         "Not Acceptable",
                         "The server wants to return a file in a format that your browser does not accept.",
                        );
}


###############################################################################
#
# _NotFound - ahhh the dreaded 404
#
###############################################################################
sub _NotFound
{
    my $self = shift;

    return $self->_Error("404",
                         {},
                         "Not Found",
                         "The requested URL was not found on this server.  If you entered the URL manually please check your spelling and try again."
                        );
}


###############################################################################
#
# _Redirect - Excuse me.  You need to be going somewhere else...
#
###############################################################################
sub _Redirect
{
    my $self = shift;
    my $url = shift;

    return ["307",{ Location=>$url },""];
}




###############################################################################
#+-----------------------------------------------------------------------------
#| Private Socket Functions
#+-----------------------------------------------------------------------------
###############################################################################

###############################################################################
#
# _read - Read it all in.  All of it.
#
###############################################################################
sub _read
{
    my $self = shift;
    my $client = shift;

    $self->_nonblock($client);
    my $select = new IO::Select($client);
    
    my $request = "";
    my $headers = "";
    my $got_request = 0;
    my $body_length = 0;

    my $timeEnd = time+5;

    my $done = 1;
    
    while(!$got_request)
    {
        while( $request !~ /\r?\n\r?\n/s)
        {
            $self->_read_chunk($select,$client,\$request);
            return if (time >= $timeEnd);
        }
        
        if ($headers eq "")
        {
            ($headers) = ($request =~ /^(.+?\r?\n\r?\n)/s);
            if ($headers =~ /Content-Length: (\d+)/)
            {
                $body_length = $1;
            }
        }
        
        $self->_debug("READ","_read: length: request (",length($request),")");
        $self->_debug("READ","_read: length: headers (",length($headers),")");
        $self->_debug("READ","_read: length: body    (",$body_length,")");
        
        if (length($request) == (length($headers) + $body_length))
        {
            $self->_debug("READ","_read: Ok.  We got a request.");
            $got_request = 1;
        }
        else
        {
            $self->_read_chunk($select,$client,\$request);
            return if (time >= $timeEnd);
        }
    }

    return $request;
}


###############################################################################
#
# _read_chunk - Read a chunk at a time.
#
###############################################################################
sub _read_chunk
{
    my $self = shift;
    my $select = shift;
    my $client = shift;
    my $request = shift;
    
    if ($select->can_read(.01))
    {
        my $status = $client->sysread($$request,4*POSIX::BUFSIZ,length($$request));
        if (!defined($status))
        {
            $self->_debug("READ","_read_chunk: Something... isn't... right... whoa!");
        }
        elsif ($status == 0)
        {
            $self->_debug("READ","_read_chunk: End of file.");
        }
        else
        {
            $self->_debug("READ","_read_chunk: status($status)\n");
            $self->_debug("READ","_read_chunk: request($$request)\n");
        }
    }
}


###############################################################################
#
# _send - helper function to keep sending until all of the data has been
#         returned.
#
###############################################################################
sub _send
{
    my $self = shift;
    my $sock = shift;
    my $data = shift;

    if (ref($data) eq "")
    {
        return unless defined($self->_send_data($sock,$data));
    }
    if (ref($data) eq "FileHandle")
    {
        while(my $temp = <$data>)
        {
            return unless defined($self->_send_data($sock,$temp));
        }
    }

    return 1;
}


###############################################################################
#
# _send_data - helper function to keep sending until all of the data has been
#              returned.
#
###############################################################################
sub _send_data
{
    my $self = shift;
    my $sock = shift;
    my $data = shift;

    my $select = new IO::Select($sock);
    
    my $length = length($data);
    my $offset = 0;
    while (($length != 0) && $select->can_write())
    {
        $self->_debug("SEND","_send_data: offset($offset) length($length)");
        my $written = $sock->syswrite($data,$length,$offset);
        if (defined($written))
        {
            $self->_debug("SEND","_send_data: written($written)");
            $length -= $written;
            $offset += $written;
        }
        else
        {
            $self->_debug("SEND","_send_data: error");
            return;
        }
    }

    $self->_debug("SEND","_send_data: sent all data");
    return 1;
}




###############################################################################
#+-----------------------------------------------------------------------------
#| Private Server Functions
#+-----------------------------------------------------------------------------
###############################################################################

###############################################################################
#
# _forking_huntsman - Kill all of the child processes
#
###############################################################################
sub _forking_huntsman
{
    my $self = shift;

    $self->_debug("FORK","_forking_hunstman: Killing children");
    $self->_log("Killing children");
    
    $SIG{CHLD} = 'IGNORE';
 
    if (scalar(keys(%{$self->{CHILDREN}})) > 0)
    {
        kill("INT",keys(%{$self->{CHILDREN}}));
    }
}


###############################################################################
#
# _forking_process - This is a forking model.
#
###############################################################################
sub _forking_process
{
    my $self = shift;
    
    while($self->{NUMCHILDREN} < $self->{CFG}->{NUMPROC})
    {
        $self->_forking_spawn();
    }

    select(undef,undef,undef,0.1);
}


###############################################################################
#
# _forking_reaper - When a child dies, have a funeral, mourn, and then move on
#
###############################################################################
sub _forking_reaper
{
    my $self = shift;

    $SIG{CHLD} = sub{ $self->_forking_reaper(); };
    my $pid = wait;
    $self->{NUMCHILDREN}--;
    delete($self->{CHILDREN}->{$pid});
}


###############################################################################
#
# _forking_spawn - Give birth to a new child process
#
###############################################################################
sub _forking_spawn
{
    my $self = shift;

    my $pid;

    croak("Could not fork: $!") unless defined ($pid = fork);
    
    if ($pid)
    {
        $self->{CHILDREN}->{$pid} = 1;
        $self->{NUMCHILDREN}++;
        return;
    }
    else
    {
        $SIG{INT} = $SIG{TERM} = $SIG{HUP} = 'DEFAULT';
        $SIG{PIPE} = 'DEFAULT';

        my $max_clients = 20;  # Make this a config?
    
        foreach my $i (0..$max_clients)
        {
            my $client;
            if($self->{SELECT}->can_read())
            {
                $client = $self->{SOCK}->accept();
            }
            last unless defined($client);
            $self->_process($client);
        }

        exit;
    }
}


###############################################################################
#
# _process - Handle a client.
#
###############################################################################
sub _process
{
    my $self = shift;
    my $client = shift;

    $self->_debug("PROC","_process: We have a client, let's treat them well.");

    $client->autoflush(1);
            
    my $request = $self->_read($client);
            
    #------------------------------------------------------------------
    # Take the request and do the magic
    #------------------------------------------------------------------
    if (defined($request))
    {
        my ($path,$reqheaders,$env) = $self->_ReadRequest($request);
        my ($code,$headers,$response) = $self->_ProcessRequest($path,$reqheaders,$env);
        $self->_ReturnResponse($client,$reqheaders,$code,$headers,$response);
    }
    
    #------------------------------------------------------------------
    # That's it.  Close down the connection.
    #------------------------------------------------------------------
    $client->close() if ($self->{CFG}->{SSL} == 0);
    $client->close(SSL_no_shutdown=>1) if ($self->{CFG}->{SSL} == 1);
    
    $self->_debug("PROC","_process: Thanks for shopping with us!");
}


###############################################################################
#
# _single_process - This is a single process model.
#
###############################################################################
sub _single_process
{
    my $self = shift;
    my $timestop = shift;

    my $client;
    my $clientSelect;
    
    my $wait = (defined($timestop) ? $timestop - time : 10);
    $self->_debug("PROC","_single_process: Wait for $wait seconds");
    
    #------------------------------------------------------------------
    # Take the request and do the magic
    #------------------------------------------------------------------
    if ($self->{SELECT}->can_read($wait))
    {
        $self->_debug("PROC","_single_process: Incoming traffic");
        $client = $self->{SOCK}->accept();
    }
    
    if (defined($client))
    {
        $self->_process($client);
    }
}



###############################################################################
#+-----------------------------------------------------------------------------
#| Private Utility Functions
#+-----------------------------------------------------------------------------
###############################################################################

###############################################################################
#
# _accept - given an Accept line and Content-Type, is it in the list?
#
###############################################################################
sub _accept
{
    my $self = shift;
    my $accept = shift;
    my $contentType = shift;

    $accept =~ s/\s*\,\s*/\,/g;
    $accept =~ s/\s*\;\s*/\;/g;
    
    my ($mainType,$subType) = split("/",$contentType,2);

    foreach my $entry (split(",",$accept))
    {
        my ($testType,$scale) = split(";",$entry,2);
        return 1 if ($testType eq $contentType);
        return 1 if ($testType eq "$mainType/*");
        return 1 if ($testType eq "*/*");
    }

    return;
}


###############################################################################
#
# _arg - if the arg exists then use it, else use the default.
#
###############################################################################
sub _arg
{
    my $self = shift;
    my $arg = shift;
    my $default = shift;

    return (exists($self->{ARGS}->{$arg}) ? $self->{ARGS}->{$arg} : $default);
}


###############################################################################
#
# _checkAuth - return 1 if the url requires an Auth, undefined otherwise.
#
###############################################################################
sub _checkAuth
{
    my $self = shift;
    my $url = shift;

	my @url = split("/",$url);
    foreach my $i (reverse 0..$#url)
    {
        my $check = join("/",@url[0..$i]);
        if($check eq "")
        {
            $check = "/";
        }
        $self->_debug("AUTH","_checkAuth: check($check)");
        return $check if exists($self->{AUTH}->{$check});
    }

    return;
}


###############################################################################
#
# _chroot - take the path and if we are running under chroot, massage it so
#           that is cannot leave DOCROOT.
#
###############################################################################
sub _chroot
{
    my $self = shift;
    my $url = shift;

    return $url if $self->{CFG}->{NOCHROOT};

    while( $url =~ s/[^\/]+\/\.\.// ) { }
    while( $url =~ s/^\/?\.\.// ) { }
    while( $url =~ s/^\/\/+/\// ) { }

    return $url;
}


###############################################################################
#
# _date - format the date correctly for the given time.
#
###############################################################################
sub _date
{
    my $self = shift;
    my $time = shift;

    $time = time unless defined($time);

    my @times = gmtime($time);
    
    my $date = sprintf("%s, %02d %s %d %02d:%02d:%02d GMT",
                       (qw(Sun Mon Tue Wed Thu Fri Sat))[$times[6]],
                       $times[3],
                       (qw(Jan Feb Mar Apr May Jun Jul Aug Oct Nov Dec))[$times[4]],
                       $times[5]+1900,
                       $times[2],
                       $times[1],
                       $times[0]
                      );

    return $date;
}


###############################################################################
#
# _debug - print out a debug message
#
###############################################################################
sub _debug
{
    my $self = shift;
    my $zone = shift;
    my (@message) = @_;
    
    print "$zone: ",join("",@message),"\n"
        if (exists($self->{DEBUG}->{$zone}) ||
            exists($self->{DEBUG}->{ALL}));
}


###############################################################################
#
# _digest_HA1 - calculate the H(A1) per RFC2617
#
###############################################################################
sub _digest_HA1
{
    my $self = shift;
    my $auth = shift;
    my $passwd = shift;
    
    my @raw;
    push(@raw,$auth->{username});
    push(@raw,$auth->{realm});
    push(@raw,$passwd);
    
    my $raw = join(":",@raw);

    #$self->_debug("AUTH","_digest_HA1: raw($raw)");

    return Digest::MD5::md5_hex($raw);
}


###############################################################################
#
# _digest_HA2 - calculate the H(A2) per RFC2617
#
###############################################################################
sub _digest_HA2
{
    my $self = shift;
    my $auth = shift;
    my $method = shift;

    my @raw;
    push(@raw,$method);
    push(@raw,$auth->{uri});

    my $raw = join(":",@raw);

    #$self->_debug("AUTH","_digest_HA2: raw($raw)");

    return Digest::MD5::md5_hex($raw);
}


###############################################################################
#
# _digest_KD - calculate the KD() per RFC2617
#
###############################################################################
sub _digest_KD
{
    my $self = shift;
    my $auth = shift;
    my $ha1 = shift;
    my $ha2 = shift;

    my @raw;
    push(@raw,$ha1);
    push(@raw,$auth->{nonce});

    if(exists($auth->{qop}) && ($auth->{qop} eq "auth"))
    {
        push(@raw,$auth->{nc});
        push(@raw,$auth->{cnonce});
        push(@raw,$auth->{qop});
    }

    push(@raw,$ha2);
    
    my $raw = join(":",@raw);

    #$self->_debug("AUTH","_digest_KD: raw($raw)");

    return Digest::MD5::md5_hex($raw);
}


###############################################################################
#
# _log - print out the message to a log with the current time
#
###############################################################################
sub _log
{
    my $self = shift;
    my (@message) = @_;
    
    my $fh = $self->{LOG};
    
    print $fh $self->_timestamp()," - ",join("",@message),"\n";
}


###############################################################################
#
# _mimetypes - Read in the mime.types file
#
###############################################################################
sub _mimetypes
{
    my $self = shift;

    open(MT,$self->{CFG}->{MIMETYPES});
    while(<MT>)
    {
        next if /^\#/;
        next if /^\s+$/;

        my ($mime_type,$extensions) = /^(\S+)(.*?)$/;

        next if ($extensions =~ /^\s*$/);
        
        $extensions =~ s/\s+/\ /g;
        
        foreach my $ext (split(" ",$extensions))
        {
            next if ($ext eq "");

            $self->{MIMETYPES}->{$ext} = $mime_type;
        }
    }
    close(MT);
}


###############################################################################
#
# _nonblock - given a socket, make it non-blocking
#
###############################################################################
sub _nonblock
{
    my $self = shift;
    my $socket = shift;
    
    #--------------------------------------------------------------------------
    # Code copied from POE::Wheel::SocketFactory...
    # Win32 does things one way...
    #--------------------------------------------------------------------------
    if ($^O eq "MSWin32")
    {
        ioctl( $socket, 0x80000000 | (4 << 16) | (ord('f') << 8) | 126, 1) ||
            croak("Can't make socket nonblocking (win32): $!");
        return;
    }

    #--------------------------------------------------------------------------
    # And UNIX does them another
    #--------------------------------------------------------------------------
    my $flags = fcntl($socket, F_GETFL, 0) ||
        croak("Can't get flags for socket: $!\n");
    fcntl($socket, F_SETFL, $flags | O_NONBLOCK) ||
        croak("Can't make socket nonblocking: $!\n");
}


###############################################################################
#
# _nonce - produce a new nonce
#
###############################################################################
sub _nonce
{
    my $self = shift;

    return MIME::Base64::encode(time.":".$self->{PRIVATEKEY},"");
}


###############################################################################
#
# _timestamp - generic funcion for getting a timestamp.
#
###############################################################################
sub _timestamp
{
    my $self = shift;

    my ($sec,$min,$hour,$mday,$mon,$year,$wday) = localtime(time);

    my $month = ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','No
v','Dec')[$mon];
    $mon++;

    return sprintf("%d/%02d/%02d %02d:%02d:%02d",($year + 1900),$mon,$mday,$hour,$min,$sec);
}


1;

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


=head2 Start()

Starts the server based on the config options passed to new().  Returns
the port number the server is listening on, or undef if the server was
unable to start.

=head2 Stop()

Shuts down the socket connection and cleans up after itself.
  
=head2 Process(timeout)

Listens for incoming requests and responds back to them.  This function
will block, unless a timeout is specified, then it will block for that
number of seconds before returning.  Useful for embedding this into
other programs and still letting the other program get some CPU time.
  
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

use vars qw ( $VERSION $SSL );

$VERSION = "0.5";

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
    
    return $self;
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

    $self->_debug("INIT","Starting the server");

    my $port = $self->{CFG}->{PORT};
    my $scan = ($port eq "scan" ? 1 : 0);
    $port = 8000 if $scan;
    
    $self->{SOCK} = undef;

    while(!defined($self->{SOCK}))
    {
        $self->_debug("INIT","Attempting to listen on port $port");
        
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
            $self->_debug("INIT","Create an SSL socket.");
            $self->{SOCK} = new IO::Socket::SSL(LocalPort=>$port,
                                                Proto=>"tcp",
                                                Listen=>10,
                                                Reuse=>1,
                                                Blocking=>0,
                                                SSL_key_file=>$self->{CFG}->{SSL_KEY},
                                                SSL_cert_file=>$self->{CFG}->{SSL_CERT},
                                                SSL_ca_file=>$self->{CFG}->{SSL_CA},
                                                SSL_verify_mode=> 0x01);
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
        $self->_debug("INIT","Initializing forking");
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

    $self->_debug("INIT","Stopping the server");

    if ($self->{CFG}->{TYPE} eq "forking")
    {
        $self->_forking_huntsman();
    }
    
    $self->{SELECT}->remove($self->{SOCK});
    $self->{SOCK}->close();
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
#+-----------------------------------------------------------------------------
#| Private Flow Functions
#+-----------------------------------------------------------------------------
###############################################################################

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
    my $env = shift;
    
    $url = $self->_chroot($url);

    my $response;
    
    if (exists($self->{CALLBACKS}->{$url}))
    {
        $response = &{$self->{CALLBACKS}->{$url}}($env);
    }
    elsif (-e $self->{CFG}->{DOCROOT}."/$url")
    {
        $response = $self->_ServeFile($url);        
    }
    else
    {
        $response = $self->_NotFound();
    }
    
    return @{$response};
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
        $self->_debug("FILE","This is a directory, look for a index file.");
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

            $self->_debug("FILE","Show a directory listing.");
            return $self->_DirList($path);
        }
    }

    if (!(-f $fullpath))
    {
        $self->_debug("FILE","404, File not found.  Whoop! Whoop!");
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
    
    return ["200",\%headers,$fileHandle];
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
    
    my %env;

    my ($type,$url) = ($request =~ /(GET|POST)\s+(\S+)\s+/s);
    
    $self->_debug("REQ","type($type) url($url)");
    $self->_log("$type $url");
            
    my $uri = new URI($url,"http");

    my $path = $uri->path();

    foreach my $key ($uri->query_param())
    {
        $env{$key} = $uri->query_param($key);
    }

    if ($type =~ /^post$/i)
    {
        $self->_debug("REQ","We got a POST");
        $self->_debug("REQ","request($request)");
        my ($body) = ($request =~ /\r?\n\r?\n(.*?)$/s);
        $self->_debug("REQ","body($body)");

        my $post_uri = new URI("?$body","http");
        
        foreach my $key ($post_uri->query_param())
        {
            $env{$key} = $post_uri->query_param($key);
            $self->_debug("REQ","ENV: $key: $env{$key}");
        }
    }
    
    return ( $path, \%env );
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
    my $code = shift;
    my $headers = shift;
    my $response = shift;

    my $header = "HTTP/1.1 $code\n";
    $header .= "Server: Net::HTTPServer v$VERSION\n";
    $headers->{'Content-Type'} = "text/html"
        unless exists($headers->{'Content-Type'});
    foreach my $key (keys(%{$headers}))
    {
        $header .= "$key: ".$headers->{$key}."\n";
    }
    chomp($header);
    $header .= "\r\n\r\n";

    $self->_debug("RESP","----------------------------------------");
    $self->_debug("RESP",$header);
    if (($headers->{'Content-Type'} eq "text/html") ||
        ($headers->{'Content-Type'} eq "text/plain"))
    {
        $self->_debug("RESP",$response);
    }
    $self->_debug("RESP","----------------------------------------");
    
    $self->_send($client,$header);
    $self->_send($client,$response);
}




###############################################################################
#+-----------------------------------------------------------------------------
#| Private Canned Responses
#+-----------------------------------------------------------------------------
###############################################################################

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

        $res .= "<a href='$file'>$file</a><br/>\n";
    }

    $res .= "</body></html>\n";

    return ["200",{},$res];
}


###############################################################################
#
# _NotFound - ahhh the dreaded 404
#
###############################################################################
sub _NotFound
{
    my $self = shift;

    return ["404",{},<<'NOTFOUND'];
<html>
  <head>
    <title>Object not found!</title>
  </head>

  <body BGCOLOR="#FFFFFF" TEXT="#000000" LINK="#0000CC">
    <h1>Object not found!</h1>
    <dl>
      <dd>
        The requested URL was not found on this server. 

        If you entered the URL manually please check your
        spelling and try again.
      </dd>
    </dl>

    <h2>Error 404</h2>
  </body>
</html>
NOTFOUND

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
        
        $self->_debug("READ","length: request (",length($request),")");
        $self->_debug("READ","length: headers (",length($headers),")");
        $self->_debug("READ","length: body    (",$body_length,")");
        
        if (length($request) == (length($headers) + $body_length))
        {
            $self->_debug("READ","Ok.  We got a request.");
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
            $self->_debug("READ","Something... isn't... right... whoa!");
        }
        elsif ($status == 0)
        {
            $self->_debug("READ","End of file.");
        }
        else
        {
            $self->_debug("READ","status($status)\n");
            $self->_debug("READ","request($$request)\n");
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
        my $length = length($data);
        my $offset = 0;
        while ($length != 0)
        {
            my $written = $sock->syswrite($data,$length,$offset);
            $length -= $written;
            $offset += $written;
        }
    }
    if (ref($data) eq "FileHandle")
    {
        while(my $temp = <$data>)
        {
            my $length = length($temp);
            my $offset = 0;
            while ($length != 0)
            {
                my $written = $sock->syswrite($temp,$length,$offset);
                $length -= $written;
                $offset += $written;
            }
        }
    }
}




###############################################################################
#+-----------------------------------------------------------------------------
#| Private Server Functions
#+-----------------------------------------------------------------------------
###############################################################################

###############################################################################
#
# _process - Handle a client.
#
###############################################################################
sub _process
{
    my $self = shift;
    my $client = shift;

    $self->_debug("PROC","We have a client, let's treat them well.");
            
    my $request = $self->_read($client);
            
    #------------------------------------------------------------------
    # Take the request and do the magic
    #------------------------------------------------------------------
    if (defined($request))
    {
        my ($path,$env) = $self->_ReadRequest($request);
        my ($code,$headers,$response) = $self->_ProcessRequest($path,$env);
        $self->_ReturnResponse($client,$code,$headers,$response);
    }
    
    #------------------------------------------------------------------
    # That's it.  Close down the connection.
    #------------------------------------------------------------------
    $client->close();
    
    $self->_debug("PROC","Thanks for shopping with us!");
}


###############################################################################
#
# _forking_huntsman - Kill all of the child processes
#
###############################################################################
sub _forking_huntsman
{
    my $self = shift;

    $self->_debug("FORK","Killing children");
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
    
        foreach (0..$max_clients)
        {
            my $client = $self->{SOCK}->accept() or last;
            $self->_process($client);
        }

        exit;
    }
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
    $self->_debug("PROC","Wait for $wait seconds");
    
    #------------------------------------------------------------------
    # Take the request and do the magic
    #------------------------------------------------------------------
    if ($self->{SELECT}->can_read($wait))
    {
        $self->_debug("PROC","Incoming traffic");
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

    my $flags = fcntl($socket, F_GETFL, 0)
        or croak("Can't get flags for socket: $!\n");
    fcntl($socket, F_SETFL, $flags | O_NONBLOCK)
        or croak("Can't make socket nonblocking: $!\n");
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

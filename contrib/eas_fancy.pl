#!/usr/bin/perl

# Fancy EAS sessions replayer

use IO::Select;
use Term::ReadKey;
use POSIX;
use strict;

my $greener = "\x1b[1;32m";
my $green = "\x1b[0;32m";
my $yellower = "\x1b[1;33m";
my $yellow = "\x1b[0;33m";
my $blueer = "\x1b[1;34m";
my $blue = "\x1b[0;34m";
my $purpler = "\x1b[1;35m";
my $purple = "\x1b[0;35m";
my $reder = "\x1b[1;31m";
my $red = "\x1b[0;31m";
my $whiter = "\x1b[1m";
my $white = "\x1b[0m";
my $gray = "\x1b[1;30m";
my $inverted = "\x1b[7m";

sub cls {
    print "\x1b[2J";
}

sub savecursorpos {
    print "\x1b7";
}

sub restorecusorpos {
    print "\x1b8";
}

sub positioncursor {
    my $line = shift || 1;
    my $column = shift || 1;
    print "\x1b[".$line.";".$column."H";
}

sub fixedstr {
    my $s = shift;
    my $l = shift || 12;
    my $d = (shift)?'-':''; # nonempty = left, empty = right
    $s = sprintf("%${d}${l}s",$s);
    if ($d) {
        return substr($s,0,$l);
    } else {
        return substr($s,-$l);
    }
}

sub flyby {
    my @default_mod = ( '|', '/', '-', '\\' );

    my $string = shift || '';
    my $seq = shift || sprintf("%i",rand(length($string)));
    my (@modifier) = @_;
    @modifier = @default_mod unless (scalar(@modifier));
    $seq = $seq % length($string);
    my @a = split(//,$string);

    my $current_pos = @modifier[$seq % scalar(@modifier)];
    my @modifiers;
    if (ref($current_pos) eq 'ARRAY') {
        my $ii = $seq - sprintf("%i",scalar(@{$current_pos}))/2;
        foreach my $cc (@{$current_pos}) {
            @modifiers[$ii] = $cc if ($ii >= 0);
            $ii++;
        }
    } else {
        @modifiers[$seq] = $current_pos;
    }

    my $i = 0;
    my $out = '';
    foreach my $c (@a) {
        if (@modifiers[$i]) {
        #    my $cc = @modifier[$ii] || ' ';
            my $cc = @modifiers[$i];
            $cc =~ s/X/$c/;
            $out .= $cc;
        } else {
            $out .= $c;
        }
        $i++;
    }
    return $out;
}

sub terminate {
    &restorecusorpos;
    ReadMode('normal');
    print "\nExiting.\n";
    exit;
}

sub open_expr {
    $_ = shift();

    /\.bz2$/i and return "bzcat $_|";
    /\.gz$/i and return "zcat $_|";
    /\.lz(?:ma)?$/i and return "lzcat $_|";

    return "<$_";
}

sub read_session_file {
    my $f = shift;
    my $pos = shift || 0;
    seek($f,$pos,0);
    return undef if eof($f);

    my $data;

    read($f,$data,4);
    my $time=unpack("V", $data);
    read($f,$data,4);
    my $usec=unpack("V", $data);
    read($f,$data,4);
    my $hightime = "$time.$usec";
    my $len=unpack("V", $data);
    read($f,$data,$len);
    my $input='';
    my $output=$data;

    if ($output =~ /\e\^(.*?)\e\\/) {
        $input = $1;
        $output =~ s/\e\^(.*?)\e\\//;
    }

    my $pos = tell($f);

    return ($pos, $hightime, $len, $data, $input, $output);
}

sub colorize_controls {
    return &translate_controls(shift,1);
}

sub translate_controls {
    my $s = shift;
    my $c = shift || 0;
    my $cb = ($c)?$inverted:'';
    my $ce = ($c)?$white:'';
    my $b = '@@@@BEG::::';
    my $e = '@@@@END::::';
    $s =~ s/\r$//g;
    $s =~ s/\x0d/$b<CR>$e/g;
    $s =~ s/\x1b\[A/$b<UP>$e/g;
    $s =~ s/\x1b\[B/$b<DOWN>$e/g;
    $s =~ s/\x1b\[C/$b<RIGHT>$e/g;
    $s =~ s/\x1b\[D/$b<LEFT>$e/g;
    $s =~ s/([\000-\037])/sprintf "$b<%s>$e",&myord($1)/ge;
    $s =~ s/$b/$cb/g;
    $s =~ s/$e/$ce/g;
    return $s;
}

sub myord {
    my $chr = ord(shift);
    if ($chr == 27) {
        return "ESC";
    } elsif ($chr == 127) {
        return "DEL";
    } elsif ($chr == 0) {
        return "^@";
    } elsif ($chr == 18) {
        return "^R";
    } elsif ($chr > 0 && $chr < 14) { # ^A ... ^M
        return "^".chr($chr+64);
    }
    return sprintf "%03d", $chr;
}

sub dumpfile {
    my $filename = shift;
    my $session;
    my $socket = open_expr($filename);

    if (! open($session, $socket)) {
        print "Cannot open session file $filename: $!\n";
        &terminate;
    }

    my $bufin;
    my $i = 1;
    my $pos = 0;
    my ($time, $len, $input, $output);
    DUMP: while (1) {
        ($pos, $time, $len, undef, $input, $output) = &read_session_file($session, $pos);
        if ($pos eq undef) {
            last DUMP;
        }

        $bufin .= $input;
        if ($bufin =~ /\x0d/) {
            $bufin = &colorize_controls($bufin);
            printf "${yellower}<<<<<<${white} %s\n", $bufin;
            $bufin = undef;
        }

        my $datetime = POSIX::strftime("%Y-%m-%d %H:%M:%S",localtime($time));
        my $usec = $time;
        $usec =~ s/.*\.//;
        my $f = 0;
        foreach my $l (split(/\n/,$output)) {
            $l = &colorize_controls($l);
            printf "%5d  ${blue}[%s.%06d]${white} ${gray}%s%04d%s${white} %s\n", $i++, $datetime, $usec, (!$f)?'<':'+', $len, (!$f)?'>':'+', $l; #if length($l);
            $f = 1; #if length($l);
        }
    }

    close($session);
}

sub playback {
    my $filename = shift;
    my $waiteof = shift || 0;

    $| = 1;

    $SIG{INT} = \&terminate;
    $SIG{TERM} = \&terminate;

    # use select for timeouts and to monitor stdin activity
    my $select = IO::Select->new();
    $select->add(\*STDIN);

    # Term::ReadKey setup
    ReadMode('noecho');
    ReadMode('cbreak');

    my $session;
    my $socket = open_expr($filename);

    if (! open($session, $socket)) {
        print "Cannot open session file $filename: $!\n";
        &terminate;
    }

    my $compression = 0;
    if ($socket !~ /^</) {
        $compression = 1;
    }

    my $filesize = -s $filename;

    &cls;

    my $i = 0;
    my $pause = 0;
    my $timeout = 0.01;
    my $speedup = 1;
    my $direction = 0;
    my $pos = 0;
    my $time = 0;
    my $perc = 0;
    my $lasttime = 0;
    my $lastinput = 0;
    my $overlays = 1;
    my $animations = 1;
    my $forward = 0;
    my $rewind = 0;
    my $input;
    my $inputbuf = 'USER INPUT: ';
    my $terminalnote = 'this is terminal capture, not video so your screen may become garbled';
    my $output;
    my $ts;
    REPLAY: while (1) {
        my $str;
        my $str_fancy;

        my $date = strftime("%d/%m/%y",localtime($time));
        my $hour = strftime("%H:%M:%S",localtime($time));
        my $right_pane = "%5s %s %s";

        if ($pause) {
            my $str_perc = 'PAUSE';
            if ($speedup ne 1) {
                $date = sprintf("x%0.3f",$speedup);
                $date =~ s/\.?0+$//;
                $date = sprintf("%8s","<".substr($date,-6).">");
            }
            $str = "  ..:[ ".sprintf($right_pane,$str_perc,$date,$hour)." ]:..  ";
            $str = &fixedstr($str,37);
            my @fancy = ([ "${whiter}X${white}", "${whiter}X${white}", "${blueer}X${white}", "${blueer}X${white}", "${blueer}X${white}", "${blueer}X${white}", "${blueer}X${white}", "${blueer}X${white}", "${blueer}X${white}", "${blue}X${white}", "${blue}X${white}"], [ "${whiter}X${white}", "${whiter}X${white}", "${reder}X${white}", "${reder}X${white}", "${reder}X${white}", "${reder}X${white}", "${reder}X${white}", "${reder}X${white}", "${reder}X${white}", "${red}X${white}", "${red}X${white}" ]);
            $str_fancy = &flyby($str,$i,@fancy);
            $i += ($direction)?-5:5;
            $direction = 0 if ($i <= 0);
            $direction = 1 if ($i >= length($str));
            $timeout = 0.5;

        } else {

            my $lastpos = $pos;
            ($pos, $time, undef, undef, $input, $output) = &read_session_file($session, $pos);
            if ($pos eq undef) {
                if (!$compression and $waiteof) {
                    $date = 'EOF WAIT';
                    $hour = 'OR QUIT!';
                    $timeout = 0.01;
                    $speedup = 1;
                    $pos = $lastpos;
                } else {
                    last REPLAY;
                }
            }

            if ($time) {
                $ts->{$time} = $pos unless $compression;
                my $delta = time() - $time;
                $delta = -$delta if $delta < 0;
                if ($delta < 60) {
                    $date = '((LIVE))';
                } else {
                    $date = strftime("%d/%m/%y",localtime($time));
                }
                $hour = strftime("%H:%M:%S",localtime($time));
            }

            $timeout = $time - $lasttime if ($time > 0 and $lasttime > 0 and $time - $lasttime > 0);
            $lasttime = $time;

            if ($timeout > 3) {
                $timeout = 1;
                $date = '<<WARP>>';
            }

            $timeout = $timeout / $speedup;

            if ($forward > 0) {
                $date = '[| >> |]';
                if ($time < $forward) {
                    next REPLAY;
                } else {
                    print "${inverted}[[[ forwarded to ".strftime("%d/%m/%y %H:%M:%S",localtime($time))." ($pos), $terminalnote ]]]${white}";
                    $forward = 0;
                }
            }

            if (!$compression and $rewind > 0) {
                $date = '[| << |]';
                REWIND: foreach my $t (sort {$b <=> $a} keys %{$ts}) {
                    if ($rewind >= $t) {
                        $pos = $ts->{$t};
                        $time = $t;
                        print "${inverted}[[[ rewound to ".strftime("%d/%m/%y %H:%M:%S",localtime($t))." ($pos), $terminalnote ]]]${white}";
                        foreach my $tt (sort {$b <=> $a} keys %{$ts}) {
                            if ($tt >= $t) {
                                delete($ts->{$tt});
                            }
                        }
                        last REWIND;
                    }
                }
                $rewind = 0;
                next REPLAY;
            }

            if ($input) {
                $inputbuf = '' if ($lastinput > 0 and $time - $lastinput > 30);
                $inputbuf .= $input;
                $lastinput = $time;
            }

            my $str_perc;
            if ($compression) {
                $str_perc = $filename;
                $str_perc =~ s/.*\.(.*)/<$1>/;
            } else {
                $filesize = -s $filename if ($perc >= 99);
                $perc = $pos / $filesize * 100;
                $str_perc = sprintf("%i%%",$perc);
            }

            $str = "  ..:[ ".sprintf($right_pane,$str_perc,$date,$hour)." ]:..  ";
            $str = &fixedstr($str,37);
            my @fancy = ([ "${whiter}X${white}", "${whiter}X${white}", "${greener}X${white}", "${greener}X${white}", "${greener}X${white}", "${greener}X${white}", "${green}X${white}", "${green}X${white}" ]);
            $str_fancy = &flyby($str,sprintf("%i",(($timeout <= 0.01)?($i++/10):($i++))),@fancy);
        }

        print $output unless $pause;

        if ($pause or $overlays) {
            my ($wchar, $hchar, undef, undef) = GetTerminalSize();

            &savecursorpos;
            &positioncursor(1,$wchar-length($str)-10);
            print (($animations)?$str_fancy:$str);

            if ($time - $lastinput <= 30) {
                &positioncursor(1,10);
                my $maxlen = sprintf ("%i", $wchar/2-10);
                print (($animations)?
                    " ${purpler}<${white}${whiter}[${gray} ".&fixedstr(&translate_controls($inputbuf),$maxlen)." ${white}${whiter}]${purpler}>${white} " :
                    " <[ ".&fixedstr(&translate_controls($inputbuf),$maxlen)." ]> " );
            }

            &restorecusorpos;
        }

        my @fdset = $select->can_read($timeout) if $timeout > 0.0001; # https://github.com/scoopex/scriptreplay_ng/blob/master/scriptreplay#L125
        if (@fdset) {
            my $key = ReadKey(0);
            if ($key =~ /q/i) {
                &terminate;
            } elsif ($key =~ /s|p| |\n/i) {
                $pause=($pause)?0:1;
                $i=1;
            } elsif ($key =~ /-|_/i) {
                $speedup /= 2 unless ($speedup <= 0.030);
            } elsif ($key =~ /\+|=/i) {
                $speedup *= 2 unless ($speedup >= 64);
            } elsif ($key =~ /0|\)/i) {
                $speedup = 1;
            } elsif ($key =~ /o|h/i) {
                $overlays = ($overlays)?0:1;
            } elsif ($key =~ /a/i) {
                $animations = ($animations)?0:1;
            } elsif ($key =~ /\./i) {
                $forward = $time + 10;
            } elsif ($key =~ />/i) {
                $forward = $time + 60;
            } elsif ($key =~ /\]/i) {
                $forward = $time + 3600;
            } elsif ($key =~ /}/i) {
                $forward = $time + 86400;
            } elsif ($key =~ /,/i) {
                $rewind = $time - 10;
            } elsif ($key =~ /</i) {
                $rewind = $time - 60;
            } elsif ($key =~ /\[/i) {
                $rewind = $time - 3600;
            } elsif ($key =~ /{/i) {
                $rewind = $time - 86400;
            } elsif ($key =~ /f/i) {
                $pos = -s $filename unless $compression;
            }
        }
    }

    close($session);
    &terminate;
}

if ($0 =~ /eas_dumpfile/) {
    &dumpfile($ARGV[0]);
} elsif ($0 =~ /eas_playback/) {
    &playback($ARGV[0],0);
} elsif ($0 =~ /eas_liveplay/) {
    &playback($ARGV[0],1);
} else {
    die "$0: Please call me as eas_dumpfile to dump session file, eas_playback to play it interactively, eas_liveplay to snoop on live session (press ''F'' in interactive view).\n";
}


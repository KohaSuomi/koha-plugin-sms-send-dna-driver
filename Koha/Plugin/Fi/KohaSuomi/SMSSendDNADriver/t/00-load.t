#!perl -T
use Modern::Perl;
use warnings FATAL => 'all';
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'SMS::Send::DNA::Driver' ) || print "Bail out!\n";
}

diag( "Testing SMS::Send::DNA::Driver $SMS::Send::DNA::Driver::VERSION, Perl $], $^X" );
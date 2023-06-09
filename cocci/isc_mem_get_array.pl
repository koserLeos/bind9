#!/usr/bin/perl

use warnings;
use strict;
use 5.020;

sub emit {
	my %o = @_;

	my @expressions = qw[MCTX];
	push @expressions, 'OLD_PTR' if $o{put};
	push @expressions, 'NEW_PTR' if exists $o{preamble};
	push @expressions, $o{expr}->@*  if exists $o{expr};
	push @expressions, 'FLAGS' if $o{flags};
	my $expressions = join ", ", @expressions;

	my $types = join ", ", $o{type}->@* if exists $o{type};
	my $idents = join ", ", $o{ident}->@* if exists $o{ident};

	my @declarations;
	push @declarations, "expression $expressions;";
	push @declarations, "identifier $idents;" if $idents;
	push @declarations, "type $types;" if $types;
	my $declarations = join "\n", @declarations;

	my $pattern = $o{fun}
	    . ($o{flex} ? '' : $o{flags} ? 'x' : '')
	    . ($o{put} ? '(MCTX, OLD_PTR, ' : '(MCTX, ')
	    . ($o{pattern})
	    . ($o{flex} ? ')' : $o{flags} ? ', FLAGS)' : ')');

	my $replace = $o{fun}
	    . ($o{flex} ? 'fx' : $o{flags} ? 'x' : '')
	    . ($o{put} ? '(MCTX, OLD_PTR, ' : '(MCTX, ')
	    . ($o{replace})
	    . ($o{flex} ? ', 0)' : $o{flags} ? ', FLAGS)' : ')');

	if (exists $o{preamble}) {
		my $preamble = join "", map "$_;\n- ", $o{preamble}->@*;
		$pattern = $preamble
			 . "NEW_PTR = ${pattern};";
		$replace = "NEW_PTR = ${replace};";
	}

	print <<~END
	@@
	$declarations
	@@

	- $pattern
	+ $replace

	END
}

sub emit_sized;
sub emit_sized {
	my %o = @_;
	my $size = pop $o{size}->@*;
	if (defined $size) {
		push $o{type}->@*, $size;
		emit_sized %o;
		pop $o{type}->@*;
		push $o{expr}->@*, $size;
		emit_sized %o;
		pop $o{expr}->@*;
	} else {
		emit @_;
		emit @_, flags => 1 unless $o{flex};
	}
	push $o{size}->@*, $size;
}

sub emit_get_put {
	emit_sized @_, fun => 'isc_mem_get';
	emit_sized @_, put => 1, fun => 'isc_mem_put';
	emit_sized @_, put => 1, fun => 'isc_mem_putanddetach';
}

sub emit_reget {
	my %o = (@_, put => 1, fun => 'isc_mem_reget');
	emit_sized %o;
	if (exists $o{preamble}) {
		$o{preamble} = [reverse $o{preamble}->@*];
		emit_sized %o;
	}
}

emit_get_put
    size => [qw[ ELEM ]],
    expr => [qw[ COUNT ]],
    pattern => 'COUNT * sizeof(ELEM)',
    replace => 'COUNT, sizeof(ELEM)';

emit_get_put
    size => [qw[ ELEM ]],
    expr => [qw[ COUNT ]],
    pattern => 'sizeof(ELEM) * COUNT',
    replace => 'COUNT, sizeof(ELEM)';

emit_get_put
    size => [qw[ ELEM ]],
    pattern => 'sizeof(ELEM)',
    replace => '1, sizeof(ELEM)';

emit_get_put
    flex => 1,
    size => [qw[ BASE ]],
    expr => [qw[ LENGTH ]],
    pattern => 'sizeof(BASE) + LENGTH',
    replace => 'LENGTH, sizeof(char), sizeof(BASE)';

emit_get_put
    expr => [qw[ SIZE ]],
    pattern => 'SIZE',
    replace => 'SIZE, sizeof(char)';

emit_reget
    size => [qw[ ELEM ]],
    ident => [qw[ OLD_SIZE NEW_SIZE ]],
    expr => [qw[ OLD_COUNT NEW_COUNT ]],
    preamble => [ 'size_t OLD_SIZE = OLD_COUNT * sizeof(ELEM)',
		  'size_t NEW_SIZE = NEW_COUNT * sizeof(ELEM)' ],
    pattern => 'OLD_SIZE, NEW_SIZE',
    replace => 'OLD_COUNT, NEW_COUNT, sizeof(ELEM)';

emit_reget
    size => [qw[ ELEM ]],
    expr => [qw[ OLD_SIZE OLD_COUNT NEW_SIZE NEW_COUNT ]],
    preamble => [ 'OLD_SIZE = OLD_COUNT * sizeof(ELEM)',
		  'NEW_SIZE = NEW_COUNT * sizeof(ELEM)' ],
    pattern => 'OLD_SIZE, NEW_SIZE',
    replace => 'OLD_COUNT, NEW_COUNT, sizeof(ELEM)';

emit_reget
    size => [qw[ ELEM ]],
    expr => [qw[ OLD_COUNT NEW_COUNT ]],
    pattern => 'OLD_COUNT * sizeof(ELEM), NEW_COUNT * sizeof(ELEM)',
    replace => 'OLD_COUNT, NEW_COUNT, sizeof(ELEM)';

emit_reget
    expr => [qw[ OLD_SIZE NEW_SIZE ]],
    pattern => 'OLD_SIZE, NEW_SIZE',
    replace => 'OLD_SIZE, NEW_SIZE, sizeof(char)';

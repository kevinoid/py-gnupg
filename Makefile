# $Id$

# Makefile.inc should define
# XSLT_PROG
# because these variables can differ between environments.
include Makefile.inc

XSL          = sourceforge-page.xsl
XSLT_OPTIONS =
XSLT         = $(XSLT_PROG)
PHP          = php -q
ENTITIES     = entities
TIDY         = tidy -config tidyrc -m

NAVBAR_INC = navbar/navbar.inc-html
NAVBAR_XML = navbar/navbar.xml
NAVBAR_XSL = navbar/navbar.xsl

all : index.html

.PHONY : perms

$(NAVBAR_INC) : $(NAVBAR_XML) $(NAVBAR_XSL)
	$(XSLT) -s $(NAVBAR_XSL) -o $@ $<

navbar/navbar.xml : $(NAVBAR_XML).php $(ENTITIES)
	$(PHP) $< > $@

%.html : %.xml $(XSL) $(NAVBAR_INC)
	$(XSLT) -s $(XSL) -o $@ $<
	$(TIDY) $@

%.xsl : %.xsl.php $(ENTITIES)
	$(PHP) $< > $@

clean :
	find . -name "*html"	| xargs rm -f
	find . -name "*.xsl"	| xargs rm -f
	find . -name "*~"	| xargs rm -f

perms :
	chmod -R a+rX .

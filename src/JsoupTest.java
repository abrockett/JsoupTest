import org.apache.commons.lang3.StringEscapeUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Entities.EscapeMode;
import org.jsoup.safety.Cleaner;
import org.jsoup.safety.Whitelist;

public class JsoupTest {

	private static final Whitelist rallyWhitelist = new Whitelist()

			// Links
			.addTags("a")
			.addAttributes("a", "href")
			.addProtocols("a", "href", "ftp", "http", "https", "mailto")

			// Structural / Misc
			.addTags("br", "center", "div", "hr", "p", "span")

			// Lists
			.addTags("dd", "dl", "dt", "li", "ol", "ul")

			// Headers
			.addTags("h1", "h2", "h3", "h4", "h5", "h6")

			// Formatting
			.addTags("b", "blockquote", "code", "em", "font", "i", "pre",
					"small", "strike", "strong", "sub", "sup", "u")
			.addAttributes("font", "color", "face", "size")
			.addProtocols("blockquote", "http", "https")

			// Tables
			.addTags("col", "colgroup", "table", "tbody", "td", "tfoot", "th",
					"thead", "tr")

			// Images
			.addTags("img")
			.addAttributes("img", "align", "alt", "height", "src", "title",
					"width").addProtocols("img", "src", "http", "https")

			// Allow attributes on all tags
			.addAttributes(":all", "style", "width", "height")

			.preserveRelativeLinks(true);

	public static final Document.OutputSettings outputSettings = new Document.OutputSettings()
			.prettyPrint(false);

	public static void main(String[] args) {

		String unsafe = "<img src=\"%-->2F%3E<script>alert(1);</script> javascript:alert('XSS');\" /><img src=\"%-- >2F%3E<script>alert(1);</script> javascript:alert('XSS');\" />";
		String clever = "\"><<script><</script>scr</script>ipt>alert('alert')<<script></script>/<script><</script> scr</script>ipt>";
		String encoded = "&lt; &amp; &quot; &gt; < & ' \" >";
		String alert = "<script>alert('YOU GOT XSSD')</script>";
		String jsInImg = "<img src=\"javascript:alert('foo');\"/>";
		String msWordTable = "<table style=\"BORDER-COLLAPSE: collapse\"> <tbody> <tr> <td style=\"BORDER-BOTTOM: windowtext 1pt solid; BORDER-LEFT: windowtext 1pt solid; PADDING-BOTTOM: 0in; BACKGROUND-COLOR: transparent; PADDING-LEFT: 5.4pt; WIDTH: 159.6pt; PADDING-RIGHT: 5.4pt; BORDER-TOP: windowtext 1pt solid; BORDER-RIGHT: windowtext 1pt solid; PADDING-TOP: 0in; mso-border-alt: solid windowtext .5pt\" width=\"213\"> <p style=\"LINE-HEIGHT: normal; MARGIN: 0in 0in 0pt\"><font face=\"Calibri\">Row 1 col 1</font></p> </td> <td style=\"BORDER-BOTTOM: windowtext 1pt solid; BORDER-LEFT: #d4d0c8; PADDING-BOTTOM: 0in; BACKGROUND-COLOR: transparent; PADDING-LEFT: 5.4pt; WIDTH: 159.6pt; PADDING-RIGHT: 5.4pt; BORDER-TOP: windowtext 1pt solid; BORDER-RIGHT: windowtext 1pt solid; PADDING-TOP: 0in; mso-border-alt: solid windowtext .5pt; mso-border-left-alt: solid windowtext .5pt\" width=\"213\"> <p style=\"LINE-HEIGHT: normal; MARGIN: 0in 0in 0pt\"><font face=\"Calibri\">Row 1 col 2</font></p> </td> <td style=\"BORDER-BOTTOM: windowtext 1pt solid; BORDER-LEFT: #d4d0c8; PADDING-BOTTOM: 0in; BACKGROUND-COLOR: transparent; PADDING-LEFT: 5.4pt; WIDTH: 159.6pt; PADDING-RIGHT: 5.4pt; BORDER-TOP: windowtext 1pt solid; BORDER-RIGHT: windowtext 1pt solid; PADDING-TOP: 0in; mso-border-alt: solid windowtext .5pt; mso-border-left-alt: solid windowtext .5pt\" width=\"213\"> <p style=\"LINE-HEIGHT: normal; MARGIN: 0in 0in 0pt\"><font face=\"Calibri\">Row 1 col 3</font></p> </td> </tr> <tr> <td style=\"BORDER-BOTTOM: windowtext 1pt solid; BORDER-LEFT: windowtext 1pt solid; PADDING-BOTTOM: 0in; BACKGROUND-COLOR: transparent; PADDING-LEFT: 5.4pt; WIDTH: 159.6pt; PADDING-RIGHT: 5.4pt; BORDER-TOP: #d4d0c8; BORDER-RIGHT: windowtext 1pt solid; PADDING-TOP: 0in; mso-border-alt: solid windowtext .5pt; mso-border-top-alt: solid windowtext .5pt\" width=\"213\"> <p style=\"LINE-HEIGHT: normal; MARGIN: 0in 0in 0pt\"><font face=\"Calibri\">Row 2 col 1</font></p> </td> <td style=\"BORDER-BOTTOM: windowtext 1pt solid; BORDER-LEFT: #d4d0c8; PADDING-BOTTOM: 0in; BACKGROUND-COLOR: transparent; PADDING-LEFT: 5.4pt; WIDTH: 159.6pt; PADDING-RIGHT: 5.4pt; BORDER-TOP: #d4d0c8; BORDER-RIGHT: windowtext 1pt solid; PADDING-TOP: 0in; mso-border-alt: solid windowtext .5pt; mso-border-left-alt: solid windowtext .5pt; mso-border-top-alt: solid windowtext .5pt\" width=\"213\"> <p style=\"LINE-HEIGHT: normal; MARGIN: 0in 0in 0pt\"><font face=\"Calibri\">Row 2 col 2</font></p> </td> <td style=\"BORDER-BOTTOM: windowtext 1pt solid; BORDER-LEFT: #d4d0c8; PADDING-BOTTOM: 0in; BACKGROUND-COLOR: transparent; PADDING-LEFT: 5.4pt; WIDTH: 159.6pt; PADDING-RIGHT: 5.4pt; BORDER-TOP: #d4d0c8; BORDER-RIGHT: windowtext 1pt solid; PADDING-TOP: 0in; mso-border-alt: solid windowtext .5pt; mso-border-left-alt: solid windowtext .5pt; mso-border-top-alt: solid windowtext .5pt\" width=\"213\"> <p style=\"LINE-HEIGHT: normal; MARGIN: 0in 0in 0pt\"><font face=\"Calibri\">Row 2 col 3</font></p> </td> </tr> </tbody> </table>";
		String simpleMarkup = "<b>Story name</b>";

		test(unsafe);
		test(clever);
		test(encoded);
		test(alert);
		test(jsInImg);
		test(msWordTable);
		test(simpleMarkup);
	}

	private static void test(String input) {
		System.out.println("Original   : "
				+ input
				+ "\nJsoup.clean: "
				+ Jsoup.clean(input, "http://bogus-baseuri.rallydev.com",
						rallyWhitelist, outputSettings) + "\naltClean   : "
				+ multiAltClean(input) + "\naltClean2  : "
				+ multiAltClean2(input) + "\n------");
	}

	private static String altClean(String input) {
		// //https://gist.github.com/martin-naumann/2958270
		// Document doc = Jsoup.parse(input);
		// doc.outputSettings().escapeMode(EscapeMode.xhtml);
		// return doc.body().text();

		// //http://stackoverflow.com/questions/8683018/jsoup-clean-without-adding-html-entities
		// Document doc = Jsoup.parse(input);
		// doc = new Cleaner(Whitelist.simpleText()).clean(doc);
		// doc.outputSettings().escapeMode(EscapeMode.xhtml);
		// return doc.body().html();

		// http://stackoverflow.com/questions/8683018/jsoup-clean-without-adding-html-entities

		// does not work
		// String output = Jsoup.clean(input,
		// "http://bogus-baseuri.rallydev.com", rallyWhitelist, outputSettings);

		// works
		 String output = Jsoup.clean(input, rallyWhitelist);

		// does not work
//		String output = Jsoup.clean(input, "http://bogus-baseuri.rallydev.com", rallyWhitelist);

		Document doc = Jsoup.parse(output);
		// doc.outputSettings().escapeMode(EscapeMode.xhtml);
		// doc.outputSettings().prettyPrint(false);
		 return StringEscapeUtils.unescapeHtml4(doc.body().html());
//		return doc.body().html();
	}

	private static String altClean2(String input) {
		// https://gist.github.com/martin-naumann/2958270
		Document dirty = Jsoup.parseBodyFragment(input);
		dirty.outputSettings().escapeMode(EscapeMode.xhtml);
		dirty.outputSettings().prettyPrint(false);
		Document clean = new Cleaner(rallyWhitelist).clean(dirty);
		return clean.body().text();
	}

	private static String multiAltClean(String input) {
		int previousLength = input.length();
		String result = altClean(input);
		while (result.length() != previousLength) {
			previousLength = result.length();
			result = altClean(result);
		}
		return result;
	}

	private static String multiAltClean2(String input) {
		int previousLength = input.length();
		String result = altClean2(input);
		while (result.length() != previousLength) {
			previousLength = result.length();
			result = altClean2(result);
		}
		return result;
	}
}

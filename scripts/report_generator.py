"""PDF Report Generator — Markdown to PDF conversion.

Converts pentest reports from Markdown to professional PDF format.
Uses WeasyPrint for high-quality PDF generation with proper styling.

Usage:
    from scripts.report_generator import ReportGenerator

    gen = ReportGenerator()
    gen.generate_pdf("report.md", "report.pdf")
"""

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional


class ReportGenerator:
    """Generate professional PDF reports from Markdown."""

    def __init__(self):
        self.template_dir = Path(__file__).parent.parent / "resources" / "templates"
        self.template_dir.mkdir(parents=True, exist_ok=True)

    def _markdown_to_html(self, md_content: str) -> str:
        """Convert Markdown to HTML with professional styling."""
        html = md_content

        # Code blocks
        html = re.sub(
            r'```(\w*)\n(.*?)```',
            lambda m: f'<pre><code class="language-{m.group(1)}">{self._escape_html(m.group(2))}</code></pre>',
            html, flags=re.DOTALL
        )

        # Inline code
        html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)

        # Headers
        html = re.sub(r'^###### (.+)$', r'<h6>\1</h6>', html, flags=re.MULTILINE)
        html = re.sub(r'^##### (.+)$', r'<h5>\1</h5>', html, flags=re.MULTILINE)
        html = re.sub(r'^#### (.+)$', r'<h4>\1</h4>', html, flags=re.MULTILINE)
        html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)

        # Bold and italic
        html = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', html)
        html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
        html = re.sub(r'\*(.+?)\*', r'<em>\1</em>', html)

        # Tables
        lines = html.split('\n')
        in_table = False
        table_html = []
        result_lines = []

        for line in lines:
            if line.strip().startswith('|') and line.strip().endswith('|'):
                if not in_table:
                    in_table = True
                    table_html = ['<table>']
                    # Check if next line is separator
                    continue
                elif '---' in line and all(c in '|-: ' for c in line.strip()):
                    # Separator line, skip
                    continue
                else:
                    cells = [c.strip() for c in line.strip().split('|')[1:-1]]
                    if not table_html[-1].startswith('<thead'):
                        table_html.append('<thead><tr>')
                        for cell in cells:
                            table_html.append(f'<th>{cell}</th>')
                        table_html.append('</tr></thead><tbody>')
                    else:
                        table_html.append('<tr>')
                        for cell in cells:
                            table_html.append(f'<td>{cell}</td>')
                        table_html.append('</tr>')
            else:
                if in_table:
                    table_html.append('</tbody></table>')
                    result_lines.append('\n'.join(table_html))
                    in_table = False
                    table_html = []
                result_lines.append(line)

        if in_table:
            table_html.append('</tbody></table>')
            result_lines.append('\n'.join(table_html))

        html = '\n'.join(result_lines)

        # Horizontal rules
        html = re.sub(r'^---+$', '<hr>', html, flags=re.MULTILINE)

        # Line breaks
        html = html.replace('\n\n', '</p><p>')
        html = f'<p>{html}</p>'

        # Clean up empty paragraphs
        html = re.sub(r'<p>\s*</p>', '', html)
        html = re.sub(r'<p>(<h[1-6]>)', r'\1', html)
        html = re.sub(r'(</h[1-6]>)</p>', r'\1', html)
        html = re.sub(r'<p>(<table>)', r'\1', html)
        html = re.sub(r'(</table>)</p>', r'\1', html)
        html = re.sub(r'<p>(<hr>)</p>', r'\1', html)
        html = re.sub(r'<p>(<pre>)', r'\1', html)
        html = re.sub(r'(</pre>)</p>', r'\1', html)

        return html

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;'))

    def _get_css(self) -> str:
        """Return CSS for PDF styling."""
        return """
        @page {
            size: A4;
            margin: 2.5cm 2cm 2.5cm 2cm;
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 9pt;
                color: #666;
            }
            @top-right {
                content: "Project Unified-Shield — Confidential";
                font-size: 8pt;
                color: #999;
            }
        }

        @page :first {
            @top-right { content: none; }
            @bottom-center { content: none; }
        }

        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 10pt;
            line-height: 1.6;
            color: #333;
        }

        h1 {
            font-size: 22pt;
            color: #1a1a2e;
            border-bottom: 3px solid #16213e;
            padding-bottom: 8px;
            margin-top: 30px;
            page-break-before: always;
        }

        h1:first-of-type {
            page-break-before: avoid;
        }

        h2 {
            font-size: 16pt;
            color: #16213e;
            border-bottom: 2px solid #e8e8e8;
            padding-bottom: 4px;
            margin-top: 24px;
            page-break-after: avoid;
        }

        h3 {
            font-size: 13pt;
            color: #0f3460;
            margin-top: 20px;
            page-break-after: avoid;
        }

        h4 {
            font-size: 11pt;
            color: #533483;
            margin-top: 16px;
        }

        p {
            margin: 8px 0;
            text-align: justify;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 9pt;
            page-break-inside: avoid;
        }

        th {
            background-color: #16213e;
            color: white;
            padding: 8px 10px;
            text-align: left;
            font-weight: 600;
        }

        td {
            padding: 6px 10px;
            border-bottom: 1px solid #e8e8e8;
        }

        tr:nth-child(even) {
            background-color: #f8f9fa;
        }

        tr:hover {
            background-color: #e8f4f8;
        }

        pre {
            background-color: #f4f4f4;
            border: 1px solid #ddd;
            border-left: 4px solid #16213e;
            padding: 12px;
            overflow: auto;
            font-size: 8.5pt;
            font-family: 'Consolas', 'Courier New', monospace;
            page-break-inside: avoid;
        }

        code {
            background-color: #f4f4f4;
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 8.5pt;
            font-family: 'Consolas', 'Courier New', monospace;
        }

        pre code {
            background-color: transparent;
            padding: 0;
        }

        hr {
            border: none;
            border-top: 2px solid #e8e8e8;
            margin: 24px 0;
        }

        strong {
            color: #1a1a2e;
        }

        em {
            color: #555;
        }

        ul, ol {
            margin: 8px 0;
            padding-left: 24px;
        }

        li {
            margin: 4px 0;
        }

        blockquote {
            border-left: 4px solid #16213e;
            margin: 12px 0;
            padding: 8px 16px;
            background-color: #f8f9fa;
            font-style: italic;
        }
        """

    def generate_pdf(
        self,
        md_path: str,
        output_path: Optional[str] = None,
        title: str = "Penetration Test Report",
        subtitle: str = "",
        author: str = "Project Unified-Shield",
        date: Optional[str] = None,
    ) -> str:
        """Generate PDF from Markdown file.

        Args:
            md_path: Path to Markdown file
            output_path: Output PDF path (auto-generated if None)
            title: Report title
            subtitle: Report subtitle
            author: Report author
            date: Report date (auto-generated if None)

        Returns:
            Path to generated PDF
        """
        if not os.path.exists(md_path):
            raise FileNotFoundError(f"Markdown file not found: {md_path}")

        # Read markdown content
        with open(md_path) as f:
            md_content = f.read()

        # Convert to HTML
        html_content = self._markdown_to_html(md_content)

        # Build full HTML document
        if date is None:
            date = datetime.now().strftime("%B %d, %Y")

        full_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        {self._get_css()}
    </style>
</head>
<body>
    <div class="cover-page" style="
        height: 100vh;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        text-align: center;
        page-break-after: always;
    ">
        <div style="
            border: 4px solid #16213e;
            padding: 60px 80px;
            max-width: 600px;
        ">
            <h1 style="
                font-size: 28pt;
                color: #1a1a2e;
                border: none;
                margin-bottom: 20px;
            ">{title}</h1>
            {'<p style="font-size: 14pt; color: #666; margin: 20px 0;">' + subtitle + '</p>' if subtitle else ''}
            <hr style="width: 60%; margin: 30px auto;">
            <p style="font-size: 11pt; color: #333;"><strong>{author}</strong></p>
            <p style="font-size: 10pt; color: #666;">{date}</p>
            <p style="font-size: 9pt; color: #999; margin-top: 40px;">CONFIDENTIAL — For Authorized Use Only</p>
        </div>
    </div>
    {html_content}
</body>
</html>"""

        # Generate output path
        if output_path is None:
            md_file = Path(md_path)
            output_path = str(md_file.with_suffix('.pdf'))

        # Generate PDF
        try:
            from weasyprint import HTML
            HTML(string=full_html).write_pdf(output_path)
            return output_path
        except Exception as e:
            # Fallback: save HTML for manual conversion
            html_path = output_path.replace('.pdf', '.html')
            with open(html_path, 'w') as f:
                f.write(full_html)
            raise RuntimeError(
                f"PDF generation failed: {e}\n"
                f"HTML saved to: {html_path}\n"
                f"Convert manually: weasyprint {html_path} {output_path}"
            )

    def generate_from_content(
        self,
        md_content: str,
        output_path: str,
        title: str = "Penetration Test Report",
        subtitle: str = "",
        author: str = "Project Unified-Shield",
        date: Optional[str] = None,
    ) -> str:
        """Generate PDF from Markdown content string.

        Args:
            md_content: Markdown content string
            output_path: Output PDF path
            title: Report title
            subtitle: Report subtitle
            author: Report author
            date: Report date

        Returns:
            Path to generated PDF
        """
        # Write to temp file then convert
        temp_md = output_path.replace('.pdf', '.md')
        with open(temp_md, 'w') as f:
            f.write(md_content)

        return self.generate_pdf(temp_md, output_path, title, subtitle, author, date)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scripts/report_generator.py <markdown_file> [output_pdf]")
        print("\nExample:")
        print("  python scripts/report_generator.py report.md")
        print("  python scripts/report_generator.py report.md output.pdf")
        sys.exit(1)

    md_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    gen = ReportGenerator()
    try:
        pdf_path = gen.generate_pdf(md_path, output_path)
        print(f"[+] PDF generated: {pdf_path}")
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

#!/usr/bin/env python3
"""Generate PowerPoint and PDF pitch deck for Tollgate."""

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.dml.color import RGBColor
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
import os

# Colors
PRIMARY_COLOR = RGBColor(0x1E, 0x3A, 0x5F)  # Dark blue
ACCENT_COLOR = RGBColor(0x3B, 0x82, 0xF6)   # Bright blue
SUCCESS_COLOR = RGBColor(0x10, 0xB9, 0x81)  # Green
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
DARK_TEXT = RGBColor(0x1F, 0x29, 0x37)


def add_title_slide(prs, title, subtitle):
    """Add a title slide."""
    slide_layout = prs.slide_layouts[6]  # Blank
    slide = prs.slides.add_slide(slide_layout)

    # Background
    background = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height
    )
    background.fill.solid()
    background.fill.fore_color.rgb = PRIMARY_COLOR
    background.line.fill.background()

    # Title
    title_box = slide.shapes.add_textbox(Inches(0.5), Inches(2.5), Inches(9), Inches(1.5))
    tf = title_box.text_frame
    p = tf.paragraphs[0]
    p.text = title
    p.font.size = Pt(44)
    p.font.bold = True
    p.font.color.rgb = WHITE
    p.alignment = PP_ALIGN.CENTER

    # Subtitle
    sub_box = slide.shapes.add_textbox(Inches(0.5), Inches(4), Inches(9), Inches(1))
    tf = sub_box.text_frame
    p = tf.paragraphs[0]
    p.text = subtitle
    p.font.size = Pt(24)
    p.font.color.rgb = WHITE
    p.alignment = PP_ALIGN.CENTER

    return slide


def add_content_slide(prs, title, bullets, has_icon=False):
    """Add a content slide with bullets."""
    slide_layout = prs.slide_layouts[6]  # Blank
    slide = prs.slides.add_slide(slide_layout)

    # Title bar
    title_bar = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, Inches(1.2)
    )
    title_bar.fill.solid()
    title_bar.fill.fore_color.rgb = PRIMARY_COLOR
    title_bar.line.fill.background()

    # Title text
    title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(9), Inches(0.7))
    tf = title_box.text_frame
    p = tf.paragraphs[0]
    p.text = title
    p.font.size = Pt(32)
    p.font.bold = True
    p.font.color.rgb = WHITE

    # Bullets
    bullet_box = slide.shapes.add_textbox(Inches(0.7), Inches(1.5), Inches(8.5), Inches(5))
    tf = bullet_box.text_frame
    tf.word_wrap = True

    for i, bullet in enumerate(bullets):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = f"• {bullet}"
        p.font.size = Pt(20)
        p.font.color.rgb = DARK_TEXT
        p.space_after = Pt(14)

    return slide


def add_feature_slide(prs, title, description, features):
    """Add a feature highlight slide."""
    slide_layout = prs.slide_layouts[6]  # Blank
    slide = prs.slides.add_slide(slide_layout)

    # Title bar
    title_bar = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, Inches(1.2)
    )
    title_bar.fill.solid()
    title_bar.fill.fore_color.rgb = PRIMARY_COLOR
    title_bar.line.fill.background()

    # Title
    title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(9), Inches(0.7))
    tf = title_box.text_frame
    p = tf.paragraphs[0]
    p.text = title
    p.font.size = Pt(32)
    p.font.bold = True
    p.font.color.rgb = WHITE

    # Description
    desc_box = slide.shapes.add_textbox(Inches(0.5), Inches(1.4), Inches(9), Inches(0.8))
    tf = desc_box.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = description
    p.font.size = Pt(18)
    p.font.italic = True
    p.font.color.rgb = DARK_TEXT

    # Features in boxes
    y_pos = 2.3
    for feature_title, feature_desc in features:
        # Feature box
        box = slide.shapes.add_shape(
            MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.5), Inches(y_pos), Inches(9), Inches(0.9)
        )
        box.fill.solid()
        box.fill.fore_color.rgb = RGBColor(0xF0, 0xF4, 0xF8)
        box.line.color.rgb = ACCENT_COLOR

        # Feature title
        feat_box = slide.shapes.add_textbox(Inches(0.7), Inches(y_pos + 0.1), Inches(8.5), Inches(0.4))
        tf = feat_box.text_frame
        p = tf.paragraphs[0]
        p.text = feature_title
        p.font.size = Pt(16)
        p.font.bold = True
        p.font.color.rgb = PRIMARY_COLOR

        # Feature description
        feat_desc_box = slide.shapes.add_textbox(Inches(0.7), Inches(y_pos + 0.45), Inches(8.5), Inches(0.4))
        tf = feat_desc_box.text_frame
        p = tf.paragraphs[0]
        p.text = feature_desc
        p.font.size = Pt(14)
        p.font.color.rgb = DARK_TEXT

        y_pos += 1.0

    return slide


def add_demo_slide(prs, title, scenarios):
    """Add a demo scenarios slide."""
    slide_layout = prs.slide_layouts[6]  # Blank
    slide = prs.slides.add_slide(slide_layout)

    # Title bar with different color
    title_bar = slide.shapes.add_shape(
        MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, Inches(1.2)
    )
    title_bar.fill.solid()
    title_bar.fill.fore_color.rgb = SUCCESS_COLOR
    title_bar.line.fill.background()

    # Title
    title_box = slide.shapes.add_textbox(Inches(0.5), Inches(0.3), Inches(9), Inches(0.7))
    tf = title_box.text_frame
    p = tf.paragraphs[0]
    p.text = title
    p.font.size = Pt(32)
    p.font.bold = True
    p.font.color.rgb = WHITE

    # Scenarios
    y_pos = 1.5
    for i, (scenario_title, steps) in enumerate(scenarios):
        # Scenario number
        num_box = slide.shapes.add_shape(
            MSO_SHAPE.OVAL, Inches(0.5), Inches(y_pos), Inches(0.5), Inches(0.5)
        )
        num_box.fill.solid()
        num_box.fill.fore_color.rgb = ACCENT_COLOR
        num_box.line.fill.background()

        num_text = slide.shapes.add_textbox(Inches(0.5), Inches(y_pos + 0.05), Inches(0.5), Inches(0.4))
        tf = num_text.text_frame
        p = tf.paragraphs[0]
        p.text = str(i + 1)
        p.font.size = Pt(18)
        p.font.bold = True
        p.font.color.rgb = WHITE
        p.alignment = PP_ALIGN.CENTER

        # Scenario title
        title_box = slide.shapes.add_textbox(Inches(1.1), Inches(y_pos + 0.05), Inches(8), Inches(0.4))
        tf = title_box.text_frame
        p = tf.paragraphs[0]
        p.text = scenario_title
        p.font.size = Pt(18)
        p.font.bold = True
        p.font.color.rgb = DARK_TEXT

        # Steps
        steps_box = slide.shapes.add_textbox(Inches(1.1), Inches(y_pos + 0.45), Inches(8), Inches(0.8))
        tf = steps_box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = steps
        p.font.size = Pt(14)
        p.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)

        y_pos += 1.3

    return slide


def create_powerpoint():
    """Create the PowerPoint presentation."""
    prs = Presentation()
    prs.slide_width = Inches(10)
    prs.slide_height = Inches(7.5)

    # Slide 1: Title
    add_title_slide(
        prs,
        "Tollgate",
        "Enterprise Runtime Governance for AI Agents"
    )

    # Slide 2: The Problem
    add_content_slide(prs, "The Challenge", [
        "AI agents are becoming autonomous decision-makers in enterprise systems",
        "Governance needed for ENTIRE agentic flow, not just individual tool calls",
        "Traditional API gateways don't understand agent intent, context, or behavior",
        "No standardized way to enforce policies across different agent frameworks",
        "Lack of visibility into what agents are doing, why, and their track record"
    ])

    # Slide 3: The Solution
    add_content_slide(prs, "Introducing Tollgate", [
        "Runtime governance for the COMPLETE agentic flow - not just tool calls",
        "Controls: Intent (why) + Context (who) + Request (what) + Behavior (history)",
        "Policy-as-code with YAML rules: ALLOW, DENY, or escalate to human approval",
        "Agent reputation tracking influences future decisions automatically",
        "Integrates with any framework: LangChain, CrewAI, AutoGen, MCP, and more"
    ])

    # Slide 4: Full Flow Governance
    add_feature_slide(
        prs,
        "Full Agentic Flow Governance",
        "Tollgate evaluates the complete picture - not just the tool being called",
        [
            ("Intent", "WHY is the agent doing this? (action + reasoning)"),
            ("Context", "WHO is the agent? (identity, session, tenant, metadata)"),
            ("Request", "WHAT tool/action is being invoked? (name, arguments)"),
            ("Reputation", "HOW has this agent behaved? (trust score, history)"),
            ("Workflow", "DOES this need approval chain? (escalation, multi-step)"),
        ]
    )

    # Slide 5: Core Architecture
    add_feature_slide(
        prs,
        "Core Architecture",
        "A simple yet powerful control tower that wraps your entire agent runtime",
        [
            ("ControlTower", "Central enforcement point for all agent operations"),
            ("PolicyEvaluator", "YAML-based rules matching intent, context, and request"),
            ("ReputationManager", "Track agent behavior and adjust trust dynamically"),
            ("WorkflowEngine", "Multi-step approval chains and escalation paths"),
            ("AuditSink", "Complete audit trail with cryptographic verification"),
        ]
    )

    # Slide 6: Enterprise Security
    add_feature_slide(
        prs,
        "Enterprise Security Features",
        "Built-in security controls for production deployments",
        [
            ("Field-Level Encryption", "AES-256-GCM encryption for sensitive audit data"),
            ("Immutable Audit Logs", "SHA-256 hash chains prevent tampering"),
            ("Ed25519 Signatures", "Cryptographic verification of agent context"),
            ("Rate Limiting", "Protect against runaway agents and abuse"),
            ("Network Guards", "Domain allowlists and request filtering"),
        ]
    )

    # Slide 6: Policy Versioning
    add_feature_slide(
        prs,
        "Policy Versioning & Rollback",
        "Git-like version control for your governance policies",
        [
            ("Version History", "Track every policy change with author and timestamp"),
            ("Instant Rollback", "Revert to any previous policy version"),
            ("Diff Comparison", "See exactly what changed between versions"),
            ("Hot Reload", "Update policies without restarting agents"),
        ]
    )

    # Slide 7: SLO Monitoring
    add_feature_slide(
        prs,
        "SLO Monitoring & Alerting",
        "Service Level Objectives for agent governance",
        [
            ("Availability SLOs", "Track system uptime and responsiveness"),
            ("Latency Percentiles", "P50, P95, P99 decision latency tracking"),
            ("Error Rate Monitoring", "Alert on policy evaluation failures"),
            ("Approval Rate Tracking", "Monitor approval/denial ratios"),
        ]
    )

    # Slide 8: Agent Reputation
    add_feature_slide(
        prs,
        "Agent Reputation System",
        "Trust scoring with automatic privilege adjustment",
        [
            ("Dynamic Trust Scores", "0.0 to 1.0 score based on agent behavior"),
            ("Behavior Tracking", "Success, failures, policy violations, anomalies"),
            ("Adaptive Rate Limits", "Low-trust agents get stricter limits"),
            ("Time-Based Decay", "Scores naturally trend toward baseline"),
        ]
    )

    # Slide 9: Workflow Orchestration
    add_feature_slide(
        prs,
        "Workflow Orchestration",
        "Multi-step approval chains and conditional workflows",
        [
            ("Approval Chains", "Sequential or parallel multi-level approvals"),
            ("Conditional Routing", "Route based on risk level, amount, etc."),
            ("Escalation Paths", "Automatic escalation on timeout"),
            ("Workflow Templates", "Pre-built patterns for common scenarios"),
        ]
    )

    # Slide 10: Observability
    add_feature_slide(
        prs,
        "Full Observability Stack",
        "Integrate with your existing monitoring infrastructure",
        [
            ("OpenTelemetry Tracing", "Distributed tracing with span hierarchy"),
            ("Prometheus Metrics", "Export metrics to your dashboards"),
            ("Structured Logging", "JSON audit logs with correlation IDs"),
            ("CLI Tools", "Validate policies, view grants, check health"),
        ]
    )

    # Slide 11: Demo Scenarios
    add_demo_slide(
        prs,
        "Live Demo Scenarios",
        [
            ("Policy Enforcement", "Show ALLOW/DENY/ASK decisions with different tool calls"),
            ("Human Approval Flow", "Demonstrate escalation and approval workflow"),
            ("Reputation in Action", "Watch trust score change based on agent behavior"),
            ("Policy Hot Reload", "Update policy and see immediate effect"),
        ]
    )

    # Slide 12: Code Example
    add_content_slide(prs, "Simple Integration", [
        "Just 3 lines to add governance to any agent:",
        "",
        "tower = ControlTower(policy='policy.yaml')",
        "result = await tower.execute(context, intent, tool_request)",
        "# Returns: Decision with ALLOW, DENY, or ASK",
        "",
        "Works with LangChain, CrewAI, AutoGen, Anthropic MCP, and custom agents"
    ])

    # Slide 13: Test Coverage
    add_content_slide(prs, "Production Ready", [
        "535+ automated tests with comprehensive coverage",
        "SQLite and Redis backends for persistence",
        "Async-first design for high performance",
        "Type-safe with full Python type hints",
        "Extensible protocol-based architecture",
        "MIT licensed, open for enterprise adoption"
    ])

    # Slide 14: Next Steps
    add_content_slide(prs, "Next Steps", [
        "Explore the codebase and run the test suite",
        "Try the CLI tools: policy validate, grant list, health check",
        "Integrate with a sample agent to see it in action",
        "Discuss production deployment requirements",
        "Identify pilot use cases within our organization"
    ])

    # Slide 15: Thank You
    add_title_slide(
        prs,
        "Questions?",
        "Let's discuss how Tollgate can help secure our AI agents"
    )

    return prs


def create_pdf():
    """Create the PDF document."""
    doc = SimpleDocTemplate(
        "docs/Tollgate_Pitch_Deck.pdf",
        pagesize=landscape(letter),
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Title'],
        fontSize=36,
        textColor=HexColor('#1E3A5F'),
        spaceAfter=20,
        alignment=1  # Center
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=HexColor('#1E3A5F'),
        spaceBefore=30,
        spaceAfter=15
    )

    subheading_style = ParagraphStyle(
        'CustomSubheading',
        parent=styles['Heading2'],
        fontSize=18,
        textColor=HexColor('#3B82F6'),
        spaceBefore=20,
        spaceAfter=10
    )

    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=12,
        textColor=HexColor('#1F2937'),
        spaceBefore=6,
        spaceAfter=6,
        leading=18
    )

    bullet_style = ParagraphStyle(
        'CustomBullet',
        parent=styles['Normal'],
        fontSize=12,
        textColor=HexColor('#1F2937'),
        leftIndent=20,
        spaceBefore=4,
        spaceAfter=4,
        leading=16
    )

    story = []

    # Title Page
    story.append(Spacer(1, 2*inch))
    story.append(Paragraph("Tollgate", title_style))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("Enterprise Runtime Governance for AI Agents",
                          ParagraphStyle('Subtitle', parent=body_style, fontSize=18, alignment=1)))
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("Internal Technical Review",
                          ParagraphStyle('Date', parent=body_style, fontSize=14, alignment=1, textColor=HexColor('#6B7280'))))
    story.append(PageBreak())

    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))
    story.append(Paragraph(
        "Tollgate is a lightweight, framework-agnostic runtime governance layer for AI agents. "
        "Unlike simple tool-level controls, Tollgate governs the <b>entire agentic flow</b> - "
        "evaluating intent (why), context (who), request (what), and behavior history (track record) "
        "to make intelligent ALLOW/DENY/ASK decisions.",
        body_style
    ))
    story.append(Spacer(1, 0.2*inch))

    # What Tollgate Governs
    story.append(Paragraph("What Tollgate Governs", subheading_style))
    governance_data = [
        ['Dimension', 'What It Controls', 'Example'],
        ['Intent', 'WHY the agent is acting', '"Send email to customer with invoice"'],
        ['Context', 'WHO the agent is', 'Agent ID, session, tenant, trust level'],
        ['Request', 'WHAT tool/action', 'Tool name, arguments, parameters'],
        ['Reputation', 'HOW agent has behaved', 'Trust score based on history'],
        ['Workflow', 'APPROVAL requirements', 'Multi-step chains, escalation'],
    ]
    gov_table = Table(governance_data, colWidths=[1.5*inch, 2.5*inch, 4.5*inch])
    gov_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1E3A5F')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8FAFC')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#E5E7EB')),
    ]))
    story.append(gov_table)
    story.append(Spacer(1, 0.3*inch))

    # Key capabilities table
    story.append(Paragraph("Key Capabilities", subheading_style))
    capabilities_data = [
        ['Capability', 'Description'],
        ['Full Flow Governance', 'Evaluate intent + context + request + reputation together'],
        ['Policy Enforcement', 'YAML-based rules with ALLOW/DENY/ASK decisions'],
        ['Security Controls', 'Encryption, signatures, rate limiting, network guards'],
        ['Policy Versioning', 'Git-like version control with rollback'],
        ['SLO Monitoring', 'Availability, latency, and error rate tracking'],
        ['Reputation System', 'Dynamic trust scores with adaptive limits'],
        ['Workflow Orchestration', 'Multi-step approval chains and escalation'],
        ['Observability', 'OpenTelemetry tracing, metrics, structured logging'],
    ]

    cap_table = Table(capabilities_data, colWidths=[2.5*inch, 6*inch])
    cap_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1E3A5F')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8FAFC')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 11),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#E5E7EB')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(cap_table)
    story.append(PageBreak())

    # The Problem
    story.append(Paragraph("The Challenge", heading_style))
    problems = [
        "AI agents are becoming autonomous decision-makers in enterprise systems",
        "Need governance for ENTIRE agentic flow, not just individual tool calls",
        "Traditional API gateways don't understand agent intent, context, or behavior patterns",
        "No standardized way to enforce policies across different agent frameworks",
        "Lack of visibility into what agents are doing, why, and their track record",
    ]
    for p in problems:
        story.append(Paragraph(f"• {p}", bullet_style))
    story.append(Spacer(1, 0.3*inch))

    # The Solution
    story.append(Paragraph("The Solution", heading_style))
    solutions = [
        "Runtime governance for the COMPLETE agentic flow - not just tool calls",
        "Evaluates: Intent (why) + Context (who) + Request (what) + Reputation (history)",
        "Policy-as-code with YAML rules matching any combination of dimensions",
        "Agent reputation tracking influences future decisions automatically",
        "Integrates with any framework: LangChain, CrewAI, AutoGen, MCP, and more",
    ]
    for s in solutions:
        story.append(Paragraph(f"• {s}", bullet_style))
    story.append(PageBreak())

    # Feature Details
    features = [
        ("Enterprise Security", [
            "AES-256-GCM field-level encryption for sensitive audit data",
            "SHA-256 hash chains for immutable, tamper-evident audit logs",
            "Ed25519 signatures for cryptographic agent context verification",
            "Configurable rate limiting to protect against abuse",
            "Domain allowlists and network request filtering",
        ]),
        ("Policy Versioning & Rollback", [
            "Complete version history with author and timestamp tracking",
            "Instant rollback to any previous policy version",
            "Diff comparison showing exact changes between versions",
            "Hot reload capability - update policies without restarts",
            "Duplicate detection to prevent redundant versions",
        ]),
        ("SLO Monitoring & Alerting", [
            "Availability SLOs for system uptime tracking",
            "Latency percentile tracking (P50, P95, P99)",
            "Error rate monitoring with configurable thresholds",
            "Approval/denial rate tracking for governance metrics",
            "Alert deduplication and automatic recovery detection",
        ]),
        ("Agent Reputation System", [
            "Dynamic 0.0-1.0 trust scores based on behavior",
            "Tracks successes, failures, policy violations, anomalies",
            "Automatic rate limit adjustment based on trust level",
            "Time-based score decay toward configurable baseline",
            "Integration with audit sink for automatic updates",
        ]),
        ("Workflow Orchestration", [
            "Multi-step sequential or parallel approval chains",
            "Conditional routing based on context (risk level, amount, etc.)",
            "Automatic escalation paths with configurable timeouts",
            "Pre-built workflow templates for common patterns",
            "SQLite and in-memory storage backends",
        ]),
    ]

    for feature_name, feature_items in features:
        story.append(Paragraph(feature_name, subheading_style))
        for item in feature_items:
            story.append(Paragraph(f"• {item}", bullet_style))
        story.append(Spacer(1, 0.1*inch))

    story.append(PageBreak())

    # Demo Scenarios
    story.append(Paragraph("Demo Scenarios", heading_style))
    story.append(Paragraph(
        "The following scenarios can be demonstrated to showcase Tollgate's capabilities:",
        body_style
    ))
    story.append(Spacer(1, 0.2*inch))

    demos = [
        ("1. Policy Enforcement Demo",
         "Show how different tool calls receive ALLOW, DENY, or ASK decisions based on policy rules. "
         "Demonstrate pattern matching, context conditions, and grant-based overrides."),
        ("2. Human Approval Workflow",
         "Walk through a sensitive operation that requires human approval. Show the approval queue, "
         "the decision UI, and how the agent receives and processes the approval response."),
        ("3. Reputation System in Action",
         "Execute a series of operations that affect an agent's trust score. Show how low-trust "
         "agents receive stricter rate limits and may be blocked from sensitive operations."),
        ("4. Policy Hot Reload",
         "Demonstrate updating a policy file and showing immediate effect on decisions without "
         "restarting the agent. Show version history and rollback capability."),
        ("5. Workflow Orchestration",
         "Execute a multi-level approval workflow with conditional routing. Show how high-value "
         "operations route to different approval chains than standard operations."),
    ]

    for demo_title, demo_desc in demos:
        story.append(Paragraph(demo_title, subheading_style))
        story.append(Paragraph(demo_desc, body_style))
        story.append(Spacer(1, 0.1*inch))

    story.append(PageBreak())

    # Technical Details
    story.append(Paragraph("Technical Details", heading_style))

    tech_table = Table([
        ['Metric', 'Value'],
        ['Test Coverage', '535+ automated tests'],
        ['Language', 'Python 3.10+'],
        ['Async Support', 'Full async/await architecture'],
        ['Storage Backends', 'SQLite, Redis, In-Memory'],
        ['Observability', 'OpenTelemetry, Prometheus, JSON logs'],
        ['License', 'MIT'],
    ], colWidths=[3*inch, 5*inch])

    tech_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1E3A5F')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#F8FAFC')),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 11),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#E5E7EB')),
    ]))
    story.append(tech_table)
    story.append(Spacer(1, 0.3*inch))

    # Integration Example
    story.append(Paragraph("Integration Example", subheading_style))
    story.append(Paragraph(
        "Integrating Tollgate into an existing agent requires minimal code changes:",
        body_style
    ))
    story.append(Spacer(1, 0.1*inch))

    code_style = ParagraphStyle(
        'Code',
        parent=styles['Code'],
        fontSize=10,
        fontName='Courier',
        backColor=HexColor('#F1F5F9'),
        leftIndent=20,
        rightIndent=20,
        spaceBefore=10,
        spaceAfter=10,
        leading=14
    )

    code = """
from tollgate import ControlTower, AgentContext, Intent, ToolRequest

# Initialize with policy file
tower = ControlTower(policy='policy.yaml')

# Create context and intent
context = AgentContext(agent_id='agent-1', session_id='sess-1')
intent = Intent(action='fetch_data', reason='User requested report')
request = ToolRequest(tool_name='database_query', arguments={'query': '...'})

# Execute with governance
decision = await tower.execute(context, intent, request)

if decision.effect == Effect.ALLOW:
    # Proceed with tool execution
    result = await execute_tool(request)
elif decision.effect == Effect.DENY:
    # Handle denial
    return f"Operation denied: {decision.reason}"
elif decision.effect == Effect.ASK:
    # Escalate to human approval
    approval = await request_approval(decision)
    """
    story.append(Paragraph(code.replace('\n', '<br/>').replace(' ', '&nbsp;'), code_style))

    story.append(PageBreak())

    # Next Steps
    story.append(Paragraph("Recommended Next Steps", heading_style))
    next_steps = [
        ("Explore the Codebase", "Clone the repository and run the test suite to verify all features work correctly."),
        ("Try the CLI Tools", "Use 'tollgate policy validate', 'tollgate grant list', and 'tollgate health' commands."),
        ("Integrate with Sample Agent", "Create a simple agent integration to see Tollgate in action."),
        ("Discuss Production Requirements", "Identify specific security, compliance, and scalability needs."),
        ("Identify Pilot Use Cases", "Select 1-2 internal AI agent projects for initial adoption."),
    ]

    for step_title, step_desc in next_steps:
        story.append(Paragraph(step_title, subheading_style))
        story.append(Paragraph(step_desc, body_style))

    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph(
        "For questions or to schedule a deeper technical review, please reach out.",
        ParagraphStyle('Footer', parent=body_style, fontSize=14, alignment=1, textColor=HexColor('#6B7280'))
    ))

    doc.build(story)


def main():
    """Generate both PowerPoint and PDF."""
    # Create docs directory if it doesn't exist
    os.makedirs("docs", exist_ok=True)

    print("Generating PowerPoint presentation...")
    prs = create_powerpoint()
    pptx_path = "docs/Tollgate_Pitch_Deck.pptx"
    prs.save(pptx_path)
    print(f"  Created: {pptx_path}")

    print("Generating PDF document...")
    create_pdf()
    print("  Created: docs/Tollgate_Pitch_Deck.pdf")

    print("\nDone! Files created in the 'docs' directory:")
    print("  - Tollgate_Pitch_Deck.pptx (PowerPoint)")
    print("  - Tollgate_Pitch_Deck.pdf (PDF)")


if __name__ == "__main__":
    main()

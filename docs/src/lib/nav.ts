export interface NavItem {
	title: string;
	href: string;
}

export interface NavSection {
	title: string;
	badge?: string;
	defaultOpen?: boolean;
	items: NavItem[];
}

export interface FlatNavItem extends NavItem {
	section: string;
}

export function flattenNavigation(): FlatNavItem[] {
	return navigation.flatMap((s) => s.items.map((item) => ({ ...item, section: s.title })));
}

export function getPrevNext(
	pathname: string,
	basePath: string
): { prev: FlatNavItem | null; next: FlatNavItem | null } {
	const items = flattenNavigation();
	const index = items.findIndex(
		(item) =>
			pathname === `${basePath}${item.href}/` || pathname === `${basePath}${item.href}`
	);
	if (index === -1) return { prev: null, next: null };
	return {
		prev: index > 0 ? items[index - 1] : null,
		next: index < items.length - 1 ? items[index + 1] : null
	};
}

export const navigation: NavSection[] = [
	{
		title: 'Quick Start',
		defaultOpen: true,
		items: [
			{ title: 'What is Portal?', href: '/what-is-portal' },
			{ title: 'Prerequisites', href: '/prerequisites' },
			{ title: 'Getting Started', href: '/getting-started' }
		]
	},
	{
		title: 'Core Concepts',
		items: [
			{ title: 'Overview', href: '/concepts' },
			{ title: 'Architecture', href: '/architecture' },
			{ title: 'Security Model', href: '/security-model' }
		]
	},
	{
		title: 'Guides',
		items: [
			{ title: 'Self-Hosting', href: '/self-hosting' },
			{ title: 'TCP/UDP Tunneling', href: '/tcp-udp-tunneling' },
			{ title: 'SIWE Authentication', href: '/siwe-authentication' },
			{ title: 'Deployment', href: '/deployment' },
			{ title: 'Configuration', href: '/configuration' }
		]
	},
	{
		title: 'Reference',
		items: [
			{ title: 'CLI Reference', href: '/cli-reference' },
			{ title: 'API Reference', href: '/api-reference' }
		]
	}
];

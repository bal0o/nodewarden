import type { ComponentChildren } from 'preact';
import { APP_VERSION } from '@shared/app-version';

interface StandalonePageFrameProps {
  title: string;
  eyebrow?: ComponentChildren;
  titleAccessory?: ComponentChildren;
  children: ComponentChildren;
}

export default function StandalonePageFrame(props: StandalonePageFrameProps) {
  return (
    <div className="standalone-shell">
      <div className="standalone-brand standalone-brand-outside">
        <img src="/nodewarden-logo.svg" alt="HomeWarden logo" className="standalone-brand-logo" />
        <div>
          <span className="standalone-brand-wordmark" role="img" aria-label="HomeWarden" />
        </div>
      </div>

      <div className="auth-card">
        {props.eyebrow && <div className="standalone-eyebrow">{props.eyebrow}</div>}
        <div className="standalone-title-row">
          <h1 className="standalone-title">{props.title}</h1>
          {props.titleAccessory}
        </div>
        {props.children}
      </div>

      <div className="standalone-footer">
        <a href="https://github.com/bal0o/nodewarden" target="_blank" rel="noreferrer">HomeWarden</a>
        <span> | </span>
        <a href="https://github.com/bal0o" target="_blank" rel="noreferrer">Author: @bal0o</a>
        <span> | </span>
        <a href="https://github.com/shuaiplus/NodeWarden" target="_blank" rel="noreferrer">Fork of NodeWarden</a>
        <span> | </span>
        <a
          href="https://github.com/bal0o/nodewarden"
          target="_blank"
          rel="noreferrer"
          className="standalone-version"
        >
          v{APP_VERSION}
        </a>
      </div>
    </div>
  );
}
